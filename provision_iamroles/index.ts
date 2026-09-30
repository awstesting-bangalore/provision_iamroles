import * as aws from "@pulumi/aws";
import * as pulumi from "@pulumi/pulumi";
import * as fs from "fs";
import * as path from "path";
import * as yaml from "js-yaml";
import {
  GetRoleCommand,
  IAMClient,
  UpdateAssumeRolePolicyCommand,
} from "@aws-sdk/client-iam";
import { fromTemporaryCredentials } from "@aws-sdk/credential-providers";
import { GetCallerIdentityCommand, STSClient } from "@aws-sdk/client-sts";

type RoleScope = "global" | "standard" | "account-specific";
type RoleEntry = string | Record<string, string[]>;

interface ParsedRole {
  roleName: string;
  policyRefs: string[];
  scope: RoleScope;
}

interface GlobalRolesFile {
  global?: RoleEntry[];
}

interface StandardRolesFile {
  standard?: Record<string, RoleEntry[]>;
}

interface AccountSpecificRolesFile {
  "account-specific"?: Record<string, RoleEntry[]>;
}

interface CustomerPolicyReference {
  type: "customer";
  name: string;
  filePath: string;
}

type TrustPolicyStatement = {
  Sid?: string;
  Effect?: string;
  Principal?: unknown;
  Action?: string | string[];
  Resource?: string | string[];
  Condition?: unknown;
};

type TrustPolicyDocument = {
  Version: string;
  Statement: TrustPolicyStatement[];
};

interface RestoreTrustInputs {
  accountId: string;
  orgAccountId: string;
  bootstrapRoleArn: string;
  permanentRoleArn: string;
  temporaryPrincipalArn: string;
  organizationAccountAccessRoleName: string;
  region: string;
}

interface RestoreTrustResourceArgs {
  accountId: pulumi.Input<string>;
  orgAccountId: pulumi.Input<string>;
  bootstrapRoleArn: pulumi.Input<string>;
  permanentRoleArn: pulumi.Input<string>;
  temporaryPrincipalArn: pulumi.Input<string>;
  organizationAccountAccessRoleName: pulumi.Input<string>;
  region: pulumi.Input<string>;
}

interface RestoreTrustOutputs extends RestoreTrustInputs {
  status: string;
  verifiedCallerArn: string;
}

export interface ProvisionIamRolesArgs {
  accountId: string;
  department: string;
  identityAccountId: string;
  orgAccountId: string;
  region?: string;

  /**
   * AWS role this component assumes to manage IAM in the target account.
   * For initial new-account provisioning this can be
   * OrganizationAccountAccessRole. For later reconciliation, pass the
   * permanent target-account administration role.
   */
  targetRoleArn?: string;

  staticTags?: Record<string, string>;
  rolesDir?: string;
  policiesDir?: string;
  trustRelationshipsDir?: string;

  /**
   * Set true only for accounts that received the temporary Stage 1 trust
   * grant. Keep it true for the lifetime of that account stack so the
   * completion marker remains in Pulumi state.
   */
  restoreOrganizationAccountAccessRoleTrust?: boolean;

  /**
   * Exact identity-account principal added temporarily by Stage 1.
   * Defaults to arn:aws:iam::<identityAccountId>:role/AE-AWS-IAC.
   */
  temporaryTrustPrincipalArn?: string;

  /**
   * Permanent target-account role that must be assumable before temporary
   * OrganizationAccountAccessRole access is removed.
   */
  validatePermanentTargetRoleArn?: string;

  /**
   * Normally OrganizationAccountAccessRole.
   */
  organizationAccountAccessRoleName?: string;
}


// -----------------------------------------------------------------------------
// One-time OrganizationAccountAccessRole trust restoration
// -----------------------------------------------------------------------------

const sleep = (milliseconds: number): Promise<void> =>
  new Promise((resolve) => setTimeout(resolve, milliseconds));

const isRetryableIamPropagationError = (err: unknown): boolean => {
  const name = String((err as any)?.name ?? "");
  const message = String((err as any)?.message ?? err ?? "");

  return [
    "AccessDenied",
    "AccessDeniedException",
    "NoSuchEntity",
    "NoSuchEntityException",
  ].includes(name) ||
    /not authorized to perform/i.test(message) ||
    /cannot be assumed/i.test(message) ||
    /does not exist/i.test(message);
};

const retryWithBackoff = async <T>(
  label: string,
  operation: () => Promise<T>,
): Promise<T> => {
  const attempts = 6;
  let lastError: unknown;

  for (let attempt = 1; attempt <= attempts; attempt++) {
    try {
      return await operation();
    } catch (err) {
      lastError = err;
      const retryable = isRetryableIamPropagationError(err);

      pulumi.log.warn(
        `[trust-restore] ${label} attempt ${attempt}/${attempts} failed: ${String(
          (err as any)?.message ?? err,
        )}`,
      );

      if (!retryable || attempt === attempts) {
        throw err;
      }

      await sleep(2000 * Math.pow(2, attempt - 1));
    }
  }

  throw lastError;
};

const decodeTrustPolicy = (
  encodedPolicy: string | undefined,
): TrustPolicyDocument => {
  if (!encodedPolicy) {
    return { Version: "2012-10-17", Statement: [] };
  }

  let decodedPolicy = encodedPolicy;
  try {
    decodedPolicy = decodeURIComponent(encodedPolicy.replace(/\+/g, "%20"));
  } catch {
    // AWS may already return plain JSON.
  }

  const parsed = JSON.parse(decodedPolicy) as Partial<TrustPolicyDocument>;
  return {
    Version: parsed.Version || "2012-10-17",
    Statement: Array.isArray(parsed.Statement) ? parsed.Statement : [],
  };
};

const actionAllowsAssumeRole = (action: unknown): boolean =>
  action === "sts:AssumeRole" ||
  (Array.isArray(action) && action.includes("sts:AssumeRole"));

const principalContainsArn = (
  principal: unknown,
  principalArn: string,
): boolean => {
  if (typeof principal === "string") {
    return principal === principalArn;
  }

  if (Array.isArray(principal)) {
    return principal.includes(principalArn);
  }

  if (!principal || typeof principal !== "object") {
    return false;
  }

  const awsPrincipal = (principal as Record<string, unknown>).AWS;
  return typeof awsPrincipal === "string"
    ? awsPrincipal === principalArn
    : Array.isArray(awsPrincipal) && awsPrincipal.includes(principalArn);
};

const trustPolicyContainsPrincipal = (
  policy: TrustPolicyDocument,
  principalArn: string,
): boolean =>
  policy.Statement.some(
    (statement) =>
      statement.Effect === "Allow" &&
      actionAllowsAssumeRole(statement.Action) &&
      principalContainsArn(statement.Principal, principalArn),
  );

const removeArnFromPrincipal = (
  principal: unknown,
  principalArn: string,
): { principal?: unknown; removed: boolean } => {
  if (typeof principal === "string") {
    return principal === principalArn
      ? { removed: true }
      : { principal, removed: false };
  }

  if (Array.isArray(principal)) {
    const remaining = principal.filter((value) => value !== principalArn);
    return {
      principal: remaining.length > 0 ? remaining : undefined,
      removed: remaining.length !== principal.length,
    };
  }

  if (!principal || typeof principal !== "object") {
    return { principal, removed: false };
  }

  const principalObject = {
    ...(principal as Record<string, unknown>),
  };
  const awsPrincipal = principalObject.AWS;
  let removed = false;

  if (typeof awsPrincipal === "string" && awsPrincipal === principalArn) {
    delete principalObject.AWS;
    removed = true;
  } else if (Array.isArray(awsPrincipal)) {
    const remaining = awsPrincipal.filter((value) => value !== principalArn);
    if (remaining.length !== awsPrincipal.length) {
      removed = true;
      if (remaining.length === 0) {
        delete principalObject.AWS;
      } else {
        principalObject.AWS = remaining.length === 1 ? remaining[0] : remaining;
      }
    }
  }

  return {
    principal: Object.keys(principalObject).length > 0
      ? principalObject
      : undefined,
    removed,
  };
};

const removeTemporaryPrincipal = (
  policy: TrustPolicyDocument,
  temporaryPrincipalArn: string,
): { policy: TrustPolicyDocument; changed: boolean } => {
  let changed = false;
  const statements: TrustPolicyStatement[] = [];

  for (const statement of policy.Statement) {
    if (
      statement.Effect !== "Allow" ||
      !actionAllowsAssumeRole(statement.Action)
    ) {
      statements.push(statement);
      continue;
    }

    const result = removeArnFromPrincipal(
      statement.Principal,
      temporaryPrincipalArn,
    );

    if (!result.removed) {
      statements.push(statement);
      continue;
    }

    changed = true;
    if (result.principal !== undefined) {
      statements.push({ ...statement, Principal: result.principal });
    }
  }

  return {
    policy: { Version: policy.Version || "2012-10-17", Statement: statements },
    changed,
  };
};

const verifyPermanentRole = async (
  inputs: RestoreTrustInputs,
): Promise<string> => {
  const client = new STSClient({
    region: inputs.region,
    credentials: fromTemporaryCredentials({
      params: {
        RoleArn: inputs.permanentRoleArn,
        RoleSessionName: `pulumi-verify-${inputs.accountId}`,
      },
    }),
  });

  const identity = await retryWithBackoff(
    `assume permanent role ${inputs.permanentRoleArn}`,
    () => client.send(new GetCallerIdentityCommand({})),
  );

  if (identity.Account !== inputs.accountId) {
    throw new Error(
      `Permanent role verification returned account '${identity.Account ?? "unknown"}', ` +
      `expected '${inputs.accountId}'`,
    );
  }

  if (!identity.Arn) {
    throw new Error("Permanent role verification did not return a caller ARN");
  }

  return identity.Arn;
};

const restoreTrust = async (
  inputs: RestoreTrustInputs,
): Promise<"restored" | "already-restored"> => {
  const client = new IAMClient({
    region: inputs.region,
    credentials: fromTemporaryCredentials({
      params: {
        RoleArn: inputs.bootstrapRoleArn,
        RoleSessionName: `pulumi-restore-${inputs.accountId}`,
      },
    }),
  });

  const roleResponse = await retryWithBackoff(
    `read ${inputs.organizationAccountAccessRoleName} trust policy`,
    () =>
      client.send(
        new GetRoleCommand({
          RoleName: inputs.organizationAccountAccessRoleName,
        }),
      ),
  );

  const currentPolicy = decodeTrustPolicy(
    roleResponse.Role?.AssumeRolePolicyDocument,
  );
  const managementRootArn = `arn:aws:iam::${inputs.orgAccountId}:root`;

  if (!trustPolicyContainsPrincipal(currentPolicy, managementRootArn)) {
    throw new Error(
      `${inputs.organizationAccountAccessRoleName} trust policy does not contain ` +
      `the expected management principal '${managementRootArn}'. Refusing to modify it.`,
    );
  }

  const restored = removeTemporaryPrincipal(
    currentPolicy,
    inputs.temporaryPrincipalArn,
  );

  if (!restored.changed) {
    return "already-restored";
  }

  await client.send(
    new UpdateAssumeRolePolicyCommand({
      RoleName: inputs.organizationAccountAccessRoleName,
      PolicyDocument: JSON.stringify(restored.policy),
    }),
  );

  return "restored";
};

const runRestore = async (inputs: RestoreTrustInputs) => {
  pulumi.log.info(
    `[${inputs.accountId}] Verifying permanent target role ` +
    `'${inputs.permanentRoleArn}' before restoring ` +
    `${inputs.organizationAccountAccessRoleName} trust.`,
  );

  const verifiedCallerArn = await verifyPermanentRole(inputs);
  pulumi.log.info(
    `[${inputs.accountId}] Permanent target role verified as ` +
    `'${verifiedCallerArn}'.`,
  );

  const status = await restoreTrust(inputs);
  pulumi.log.info(
    status === "restored"
      ? `[${inputs.accountId}] Removed temporary principal ` +
        `'${inputs.temporaryPrincipalArn}' from ` +
        `${inputs.organizationAccountAccessRoleName} trust policy.`
      : `[${inputs.accountId}] ${inputs.organizationAccountAccessRoleName} ` +
        "trust policy was already restored.",
  );

  return {
    outs: {
      ...inputs,
      status,
      verifiedCallerArn,
    },
  };
};

const restoreTrustProvider:
  pulumi.dynamic.ResourceProvider<RestoreTrustInputs, RestoreTrustOutputs> = {
    async create(inputs) {
      const { outs } = await runRestore(inputs);
      return {
        id: `${inputs.accountId}-organization-account-access-role-restored`,
        outs,
      };
    },

    async diff(_id, olds, news) {
      const legacyMarker =
        !olds.orgAccountId ||
        !olds.bootstrapRoleArn ||
        !olds.permanentRoleArn ||
        !olds.temporaryPrincipalArn ||
        !olds.organizationAccountAccessRoleName ||
        !olds.region;

      // Upgrade the old marker state without repeating the AWS operation.
      if (legacyMarker) {
        return { changes: true };
      }

      const immutableInputs: Array<keyof RestoreTrustInputs> = [
        "accountId",
        "orgAccountId",
        "bootstrapRoleArn",
        "permanentRoleArn",
        "temporaryPrincipalArn",
        "organizationAccountAccessRoleName",
        "region",
      ];
      const changedInputs = immutableInputs.filter(
        (key) => olds[key] !== news[key],
      );

      if (changedInputs.length > 0) {
        throw new Error(
          `Trust restoration marker inputs are immutable after completion. ` +
          `Changed: ${changedInputs.join(", ")}`,
        );
      }

      return { changes: false };
    },

    async update(_id, olds, news) {
      // Legacy-marker migration only. Never call AWS from update().
      return {
        outs: {
          ...news,
          status: olds.status || "legacy-marker-adopted",
          verifiedCallerArn: olds.verifiedCallerArn || "",
        },
      };
    },

    async delete() {
      // Completion marker only. Never modify AWS during deletion.
    },
  };

class RestoreTrustResource extends pulumi.dynamic.Resource {
  public readonly status!: pulumi.Output<string>;
  public readonly verifiedCallerArn!: pulumi.Output<string>;

  constructor(
    name: string,
    args: RestoreTrustResourceArgs,
    opts?: pulumi.CustomResourceOptions,
  ) {
    super(restoreTrustProvider, name, args, opts);
  }
}


// -----------------------------------------------------------------------------
// Component
// -----------------------------------------------------------------------------

export class ProvisionIamRoles extends pulumi.ComponentResource {
  public readonly roleNames: pulumi.Output<string[]>;
  public readonly restoreTrustStatus: pulumi.Output<string>;

  private readonly accountId: string;
  private readonly department: string;
  private readonly identityAccountId: string;
  private readonly orgAccountId: string;
  private readonly region: string;
  private readonly rolesDir: string;
  private readonly policiesDir: string;
  private readonly trustRelationshipsDir: string;
  private readonly staticTags: Record<string, string>;


  private readonly customerPolicyCache:
    Record<string, aws.iam.Policy> = {};

  private readonly deploymentResources:
    pulumi.Resource[] = [];


  constructor(
    name: string,
    args: ProvisionIamRolesArgs,
    opts?: pulumi.ComponentResourceOptions,
  ) {
    super(
      "aenetworks:aws:ProvisionIamRoles",
      name,
      {},
      opts,
    );

    this.accountId = args.accountId;
    this.department = args.department.trim();
    this.identityAccountId = args.identityAccountId.trim();
    this.orgAccountId = args.orgAccountId.trim();
    this.region = args.region || "us-east-1";
    this.staticTags = args.staticTags || {};

    this.rolesDir =
      args.rolesDir ||
      path.resolve(
        __dirname,
        "..",
        "roles",
      );

    this.policiesDir =
      args.policiesDir ||
      path.resolve(
        __dirname,
        "..",
        "policies",
      );

    this.trustRelationshipsDir =
      args.trustRelationshipsDir ||
      path.resolve(
        __dirname,
        "..",
        "trust_relationships",
      );


    if (
      !/^\d{12}$/.test(
        this.accountId,
      )
    ) {
      throw new Error(
        "ProvisionIamRoles requires a 12-digit accountId",
      );
    }

    if (!this.department) {
      throw new Error(
        "ProvisionIamRoles requires department",
      );
    }

    if (!this.identityAccountId) {
      throw new Error(
        "ProvisionIamRoles requires identityAccountId",
      );
    }

    if (!this.orgAccountId) {
      throw new Error(
        "ProvisionIamRoles requires orgAccountId",
      );
    }


    // -------------------------------------------------------------------------
    // Trust restoration configuration
    // -------------------------------------------------------------------------

    const shouldRestoreTrust =
      args.restoreOrganizationAccountAccessRoleTrust ??
      false;

    const organizationAccountAccessRoleName =
      args.organizationAccountAccessRoleName
        ?.trim() ||
      "OrganizationAccountAccessRole";

    const temporaryTrustPrincipalArn =
      args.temporaryTrustPrincipalArn
        ?.trim() ||
      `arn:aws:iam::${this.identityAccountId}:role/AE-AWS-IAC`;

    const validatePermanentTargetRoleArn =
      args.validatePermanentTargetRoleArn
        ?.trim();

    const bootstrapRoleArn =
      `arn:aws:iam::${this.accountId}:role/${organizationAccountAccessRoleName}`;

    const targetRoleArn =
      args.targetRoleArn
        ?.trim() ||
      bootstrapRoleArn;

    if (
      !targetRoleArn.startsWith(
        `arn:aws:iam::${this.accountId}:role/`,
      )
    ) {
      throw new Error(
        `targetRoleArn must reference target account ${this.accountId}`,
      );
    }

    // Never allow IAM resources from this component to fall back into the
    // identity account. The provider explicitly assumes a role in accountId,
    // and allowedAccountIds makes the provider fail closed if credentials ever
    // resolve to a different AWS account.
    const targetProvider =
      new aws.Provider(
        `${name}-target`,
        {
          region:
            this.region,

          allowedAccountIds: [
            this.accountId,
          ],

          assumeRoles: [
            {
              roleArn:
                targetRoleArn,

              sessionName:
                `pulumi-iam-${this.accountId}`,
            },
          ],
        },
        {
          parent:
            this,
        },
      );

    if (
      shouldRestoreTrust &&
      !validatePermanentTargetRoleArn
    ) {
      throw new Error(
        "ProvisionIamRoles requires validatePermanentTargetRoleArn when restoreOrganizationAccountAccessRoleTrust is true",
      );
    }

    if (
      validatePermanentTargetRoleArn &&
      !validatePermanentTargetRoleArn.startsWith(
        `arn:aws:iam::${this.accountId}:role/`,
      )
    ) {
      throw new Error(
        `validatePermanentTargetRoleArn must reference target account ${this.accountId}`,
      );
    }


    pulumi.log.info(
      "=== AWS IAM Roles deployment starting ===",
    );

    pulumi.log.info(
      `Target account : ${this.accountId}`,
    );

    pulumi.log.info(
      `Department : ${this.department}`,
    );

    pulumi.log.info(
      `Identity account: ${this.identityAccountId}`,
    );

    pulumi.log.info(
      `IAM target provider role: ${targetRoleArn}`,
    );

    pulumi.log.info(
      shouldRestoreTrust
        ? `Permanent target role to verify: ${validatePermanentTargetRoleArn}`
        : "OrganizationAccountAccessRole trust restoration: not required",
    );


    // -------------------------------------------------------------------------
    // Resolve and provision IAM roles
    // -------------------------------------------------------------------------

    const roles =
      this.resolveRoles();

    pulumi.log.info(
      `Resolved ${roles.length} IAM role(s) for account`,
    );


    roles.forEach(
      (role) =>
        this.provisionRole(
          role,
          targetProvider,
        ),
    );


    // -------------------------------------------------------------------------
    // One-time trust restoration marker
    //
    // Keep restoreOrganizationAccountAccessRoleTrust=true in all later
    // cumulative stages for newly created accounts. The dynamic resource runs
    // only on its initial create; later previews and updates are no-ops.
    // -------------------------------------------------------------------------

    let restoreTrustResource:
      RestoreTrustResource |
      undefined;

    if (
      shouldRestoreTrust &&
      validatePermanentTargetRoleArn
    ) {
      restoreTrustResource =
        new RestoreTrustResource(
          `${name}-restore-organization-account-access-role-trust`,
          {
            accountId:
              this.accountId,
            orgAccountId:
              this.orgAccountId,
            bootstrapRoleArn:
              bootstrapRoleArn,
            permanentRoleArn:
              validatePermanentTargetRoleArn,
            temporaryPrincipalArn:
              temporaryTrustPrincipalArn,
            organizationAccountAccessRoleName:
              organizationAccountAccessRoleName,
            region:
              this.region,
          },
          {
            parent:
              this,
            dependsOn:
              this.deploymentResources,
            protect:
              true,
          },
        );
    }


    this.roleNames =
      pulumi.output(
        roles.map(
          (role) =>
            role.roleName,
        ),
      );

    this.restoreTrustStatus =
      restoreTrustResource
        ? restoreTrustResource.status
        : pulumi.output(
            "not-required",
          );


    this.registerOutputs({
      roleNames:
        this.roleNames,
      restoreTrustStatus:
        this.restoreTrustStatus,
      restoreTrustVerifiedCallerArn:
        restoreTrustResource
          ? restoreTrustResource.verifiedCallerArn
          : pulumi.output(
              "",
            ),
    });
  }


  // ---------------------------------------------------------------------------
  // YAML / role resolution
  // ---------------------------------------------------------------------------

  private loadYaml<T>(
    filePath: string,
  ): T | undefined {
    return fs.existsSync(filePath)
      ? (
          yaml.load(
            fs.readFileSync(
              filePath,
              "utf-8",
            ),
          ) as T
        )
      : undefined;
  }


  private parseRoleEntries(
    entries: RoleEntry[] | undefined,
    scope: RoleScope,
  ): ParsedRole[] {
    if (!Array.isArray(entries)) {
      return [];
    }

    return entries.map(
      (
        entry,
      ): ParsedRole => {

        if (typeof entry === "string") {
          return {
            roleName:
              entry.trim(),

            policyRefs:
              [],

            scope:
              scope,
          };
        }

        const roleNames =
          Object.keys(entry);

        if (roleNames.length !== 1) {
          throw new Error(
            `Invalid ${scope} role entry. Each entry must contain exactly one role.`,
          );
        }

        const roleName =
          roleNames[0].trim();

        const policies =
          entry[roleNames[0]];

        return {
          roleName:
            roleName,

          policyRefs:
            Array.isArray(policies)
              ? policies
                  .map(
                    (policy) =>
                      String(policy).trim(),
                  )
                  .filter(Boolean)
              : [],

          scope:
            scope,
        };
      },
    );
  }


  private getGlobalRoles():
    ParsedRole[] {

    const catalog =
      this.loadYaml<GlobalRolesFile>(
        path.join(
          this.rolesDir,
          "global.yml",
        ),
      ) || {};

    return this.parseRoleEntries(
      catalog.global,
      "global",
    );
  }


  private getStandardRoles():
    ParsedRole[] {

    const catalog =
      this.loadYaml<StandardRolesFile>(
        path.join(
          this.rolesDir,
          "standard.yml",
        ),
      ) || {};

    const departments =
      catalog.standard || {};

    const departmentName =
      Object.keys(
        departments,
      ).find(
        (key) =>
          key
            .trim()
            .toLowerCase() ===
          this.department.toLowerCase(),
      );

    if (!departmentName) {
      pulumi.log.info(
        `No standard IAM roles configured for department '${this.department}'`,
      );

      return [];
    }

    return this.parseRoleEntries(
      departments[departmentName],
      "standard",
    );
  }


  private getAccountSpecificRoles():
    ParsedRole[] {

    const catalog =
      this.loadYaml<AccountSpecificRolesFile>(
        path.join(
          this.rolesDir,
          "account-specific.yml",
        ),
      ) || {};

    return this.parseRoleEntries(
      catalog[
        "account-specific"
      ]?.[
        this.accountId
      ],
      "account-specific",
    );
  }


  private resolveRoles():
    ParsedRole[] {

    const resolved =
      new Map<
        string,
        ParsedRole
      >();

    const mergeRoles =
      (
        roles:
          ParsedRole[],
      ) => {

        for (
          const role
          of roles
        ) {
          const existing =
            resolved.get(
              role.roleName,
            );

          if (!existing) {
            resolved.set(
              role.roleName,
              {
                ...role,

                policyRefs:
                  [
                    ...role.policyRefs,
                  ],
              },
            );
          } else {
            existing.policyRefs =
              [
                ...new Set([
                  ...existing.policyRefs,
                  ...role.policyRefs,
                ]),
              ];
          }
        }
      };


    mergeRoles(
      this.getGlobalRoles(),
    );

    mergeRoles(
      this.getStandardRoles(),
    );

    mergeRoles(
      this.getAccountSpecificRoles(),
    );


    return [
      ...resolved.values(),
    ];
  }


  // ---------------------------------------------------------------------------
  // Policy resolution
  // ---------------------------------------------------------------------------

  private findCustomerPolicy(
    roleName: string,
    policyRef: string,
  ):
    CustomerPolicyReference |
    undefined {

    const customerBase =
      path.join(
        this.policiesDir,
        "customer_managed_policies",
      );

    const ownPolicy =
      path.join(
        customerBase,
        roleName,
        `${policyRef}.json`,
      );


    if (
      fs.existsSync(
        ownPolicy,
      )
    ) {
      return {
        type:
          "customer",

        name:
          policyRef,

        filePath:
          ownPolicy,
      };
    }


    if (
      !fs.existsSync(
        customerBase,
      )
    ) {
      return undefined;
    }


    for (
      const folder
      of fs.readdirSync(
        customerBase,
      )
    ) {
      if (
        folder ===
        roleName
      ) {
        continue;
      }

      const candidate =
        path.join(
          customerBase,
          folder,
          `${policyRef}.json`,
        );

      if (
        fs.existsSync(
          candidate,
        )
      ) {
        pulumi.log.info(
          `Resolved '${policyRef}' as cross-role customer managed policy from ${candidate}`,
        );

        return {
          type:
            "customer",

          name:
            policyRef,

          filePath:
            candidate,
        };
      }
    }


    return undefined;
  }


  private resolvePolicy(
    roleName: string,
    policyRef: string,
  ):
    string |
    CustomerPolicyReference {

    if (
      policyRef.startsWith(
        "arn:",
      )
    ) {
      return policyRef;
    }


    const customerPolicy =
      this.findCustomerPolicy(
        roleName,
        policyRef,
      );


    if (customerPolicy) {
      return customerPolicy;
    }


    const candidates =
      [
        "yml",
        "yaml",
      ].map(
        (extension) =>
          path.join(
            this.policiesDir,
            "aws_managed_policies",
            `${policyRef}.${extension}`,
          ),
      );


    for (
      const file
      of candidates
    ) {
      if (
        !fs.existsSync(
          file,
        )
      ) {
        continue;
      }


      const doc =
        yaml.load(
          fs.readFileSync(
            file,
            "utf-8",
          ),
        ) as
          | string
          | {
              name?: string;
              arn?: string;
            };


      if (
        typeof doc ===
        "string"
      ) {
        return doc.startsWith(
          "arn:",
        )
          ? doc
          : `arn:aws:iam::aws:policy/${doc}`;
      }


      if (doc?.arn) {
        return doc.arn;
      }


      if (doc?.name) {
        return `arn:aws:iam::aws:policy/${doc.name}`;
      }


      throw new Error(
        `Invalid AWS managed policy file '${file}'`,
      );
    }


    throw new Error(
      `Policy '${policyRef}' referenced by role '${roleName}' was not found in the policy catalogs`,
    );
  }


  // ---------------------------------------------------------------------------
  // Trust policies
  // ---------------------------------------------------------------------------

  private readFirstExisting(
    candidates: string[],
    fallback: () => string,
  ): string {
    for (
      const file
      of candidates
    ) {
      if (
        fs.existsSync(
          file,
        )
      ) {
        return fs.readFileSync(
          file,
          "utf-8",
        );
      }
    }

    return fallback();
  }


  private defaultTrustPolicy():
    string {

    return JSON.stringify({
      Version:
        "2012-10-17",

      Statement: [
        {
          Effect:
            "Allow",

          Principal: {
            AWS:
              `arn:aws:iam::${this.identityAccountId}:root`,
          },

          Action:
            "sts:AssumeRole",
        },
      ],
    });
  }


  private getTargetTrustPolicy(
    roleName: string,
  ): string {

    return this.readFirstExisting(
      [
        path.join(
          this.trustRelationshipsDir,
          `${roleName}.json`,
        ),

        path.join(
          this.trustRelationshipsDir,
          "default.json",
        ),
      ],

      () =>
        this.defaultTrustPolicy(),
    );
  }



  // ---------------------------------------------------------------------------
  // IAM roles
  // ---------------------------------------------------------------------------

  private provisionRole(
    roleConfig: ParsedRole,
    targetProvider: aws.Provider,
  ): void {

    const {
      roleName,
      policyRefs,
      scope,
    } = roleConfig;



    // Target resources use the default AWS provider.
    // ESC aws:assumeRoles points that provider at the new account.
    const role =
      new aws.iam.Role(
        `iam-${roleName}`,
        {
          name:
            roleName,

          assumeRolePolicy:
            this.getTargetTrustPolicy(
              roleName,
            ),

          tags: {
            ...this.staticTags,

            Scope:
              scope,
          },
        },
        {
          parent:
            this,

          provider:
            targetProvider,
        },
      );


    this.deploymentResources.push(
      role,
    );


    policyRefs.forEach(
      (policyRef) =>
        this.attachPolicy(
          roleName,
          role,
          policyRef,
          scope,
          targetProvider,
        ),
    );
  }


  // ---------------------------------------------------------------------------
  // Policies
  // ---------------------------------------------------------------------------

  private attachPolicy(
    roleName: string,
    role: aws.iam.Role,
    policyRef: string,
    scope: RoleScope,
    targetProvider: aws.Provider,
  ): void {

    const resolved =
      this.resolvePolicy(
        roleName,
        policyRef,
      );


    const policyArn =
      typeof resolved ===
      "string"
        ? pulumi.output(
            resolved,
          )
        : this.ensureCustomerPolicy(
            resolved,
            scope,
            targetProvider,
          ).arn;


    const label =
      typeof resolved ===
      "string"
        ? this.sanitizeName(
            policyRef,
          )
        : `cmp-${this.sanitizeName(
            resolved.name,
          )}`;


    const dependsOn =
      typeof resolved ===
      "string"
        ? [
            role,
          ]
        : [
            role,
            this.customerPolicyCache[
              resolved.name
            ],
          ];


    const attachment =
      new aws.iam.RolePolicyAttachment(
        `iam-${roleName}-${label}-attach`,
        {
          role:
            role.name,

          policyArn:
            policyArn,
        },
        {
          parent:
            this,

          provider:
            targetProvider,

          dependsOn:
            dependsOn,
        },
      );


    this.deploymentResources.push(
      attachment,
    );
  }


  private ensureCustomerPolicy(
    policyRef: CustomerPolicyReference,
    scope: RoleScope,
    targetProvider: aws.Provider,
  ): aws.iam.Policy {

    if (
      this.customerPolicyCache[
        policyRef.name
      ]
    ) {
      return this.customerPolicyCache[
        policyRef.name
      ];
    }


    const policy =
      new aws.iam.Policy(
        `cmp-${this.sanitizeName(
          policyRef.name,
        )}`,
        {
          name:
            policyRef.name,

          policy:
            fs.readFileSync(
              policyRef.filePath,
              "utf-8",
            ),

          tags: {
            ...this.staticTags,

            Scope:
              scope,

            PolicyType:
              "CustomerManaged",
          },
        },
        {
          parent:
            this,

          provider:
            targetProvider,
        },
      );


    this.customerPolicyCache[
      policyRef.name
    ] =
      policy;


    this.deploymentResources.push(
      policy,
    );


    return policy;
  }


  private sanitizeName(
    value: string,
  ): string {

    return value.replace(
      /[^a-zA-Z0-9+=,.@_-]/g,
      "-",
    );
  }
}