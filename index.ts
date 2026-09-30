import * as aws from "@pulumi/aws";
import * as pulumi from "@pulumi/pulumi";
import * as fs from "fs";
import * as path from "path";
import * as yaml from "js-yaml";
import { IAMClient, UpdateAssumeRolePolicyCommand } from "@aws-sdk/client-iam";
import { fromTemporaryCredentials } from "@aws-sdk/credential-providers";

/**
 * ----------------------------------
 * Provision IAM Roles in AWS Account.
 * ----------------------------------
 *
 * Uses the central AE-AWS-IAC role from ESC credentials, then assumes the 'OrganizationAccountAccessRole' role in the newly created AWS account to provision IAM Roles and Policies:
 *
 * - Creates IAM Roles and Policies in the target account based on the configuration in roles/iam.yml
 * - Attaches AWS Managed Policies to the roles as specified in iam.yml
 * - Attaches Customer Managed Policies from the respective Role folder under policies/customer_managed_policies/{roleName}/ to the role
 * - Attaches Trust Relationships from the respective Role folder under trust_relationships/{roleName}/ to the role
 * - Also we can attach Cross-Role Customer Managed Policies from the respective Role folder under policies/customer_managed_policies/{roleName}/ to any role
 * - Creates IAM Roles in the identity account (AE-AWS-IAC) to allow the identity account to assume the roles in the target account
 * - Creates IAM Roles in the target account to allow the identity account to assume the roles in the target account
 * - Restores the OrganizationAccountAccessRole trust policy to its original state after provisioning (For New Accounts)
 *
 * Environment variables:
 *  - PAYLOAD: The payload is passed in as a JSON string. (required)
 *    PAYLOAD example:
 *          {
 *           "account_id": "020142445569", "department": "Technology"
 *          }
 *
 * Important Note: Make sure the Pulumi config has Root Organization Account ID and its AE-AWS-IAC Role in that account configured as the default AWS provider.
 */

type RoleEntry = string | Record<string, string[]>;

interface ParsedRole {
  roleName: string;
  awsManagedPolicies: string[];
}

interface IAMRolesFile {
  iam?: RoleEntry[];
}

interface ParsedPayload {
  accountId: string;
}

interface RestoreTrustInputs {
  accountId: string;
  orgAccountId: string;
  roleArn: string;
  region: string;
}

interface RestoreTrustOutputs {
  accountId: string;
}

export interface AWSRolesAndPoliciesArgs {
  importExisting?: boolean;
  rolesDir?: string;
}

// ---------------------------------------------------------------------------
// Restore OrganizationAccountAccessRole trust
// ---------------------------------------------------------------------------

const restoreTrust = async (inputs: RestoreTrustInputs): Promise<void> => {
  const assumeRolePolicy = {
    Version: "2012-10-17",
    Statement: [
      {
        Effect: "Allow",
        Principal: { AWS: `arn:aws:iam::${inputs.orgAccountId}:root` },
        Action: "sts:AssumeRole",
      },
    ],
  };

  const client = new IAMClient({
    region: inputs.region,
    credentials: fromTemporaryCredentials({
      params: {
        RoleArn: inputs.roleArn,
        RoleSessionName: `pulumi-${inputs.accountId}`,
        ExternalId: `pulumi-${inputs.accountId}`,
      },
    }),
  });

  try {
    await client.send(
      new UpdateAssumeRolePolicyCommand({
        RoleName: "OrganizationAccountAccessRole",
        PolicyDocument: JSON.stringify(assumeRolePolicy),
      }),
    );
  } catch (err) {
    throw new Error(
      `Failed to restore OrganizationAccountAccessRole trust policy: ${String(
        (err as any)?.message ?? err,
      )}`,
    );
  }
};

const restoreTrustProvider: pulumi.dynamic.ResourceProvider<
  RestoreTrustInputs,
  RestoreTrustOutputs
> = {
  async create(inputs: RestoreTrustInputs) {
    pulumi.log.info(
      `[${inputs.accountId}] IAM roles, policies and attachments completed. Restoring OrganizationAccountAccessRole trust policy.`,
    );

    await restoreTrust(inputs);

    pulumi.log.info(
      `[${inputs.accountId}] Restored OrganizationAccountAccessRole trust policy to original state`,
    );

    return {
      id: `${inputs.accountId}-organization-account-access-role-restored`,
      outs: {
        accountId: inputs.accountId,
      },
    };
  },

  async diff() {
    return { changes: true };
  },

  async update(
    _id: string,
    _olds: RestoreTrustOutputs,
    news: RestoreTrustInputs,
  ) {
    pulumi.log.info(
      `[${news.accountId}] IAM roles, policies and attachments completed. Restoring OrganizationAccountAccessRole trust policy.`,
    );

    await restoreTrust(news);

    pulumi.log.info(
      `[${news.accountId}] Restored OrganizationAccountAccessRole trust policy to original state`,
    );

    return {
      outs: {
        accountId: news.accountId,
      },
    };
  },
};

class RestoreTrustResource extends pulumi.dynamic.Resource {
  constructor(
    name: string,
    args: RestoreTrustInputs,
    opts?: pulumi.CustomResourceOptions,
  ) {
    super(restoreTrustProvider, name, args, opts);
  }
}

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

class AWSRolesAndPolicies extends pulumi.ComponentResource {
  private readonly cfg = new pulumi.Config("awsroles");
  private readonly rolesDir: string;
  private readonly trustRelationshipsDir: string;
  private readonly identityAccountId: string;
  private readonly orgAccountId: string;
  private readonly importExisting: boolean;
  private readonly staticTags: Record<string, string>;
  private readonly payload: ParsedPayload;

  private iamRoles: Record<string, aws.iam.Role> = {};
  private identityRoles: Record<string, aws.iam.Role> = {};

  private readonly iamCatalog: IAMRolesFile;

  private identityProvider?: aws.Provider;
  private customerPolicyCache: Record<string, aws.iam.Policy> = {};
  private deploymentResources: pulumi.Resource[] = [];

  constructor(
    name: string,
    args: AWSRolesAndPoliciesArgs = {},
    opts?: pulumi.ComponentResourceOptions,
  ) {
    super("aetn:resource:AWSRolesAndPolicies", name, {}, opts);

    this.rolesDir =
      args.rolesDir || this.cfg.get("rolesDir") || "roles";
    this.trustRelationshipsDir =
      this.cfg.get("trustRelationshipsDir") ||
      process.env.TRUST_RELATIONSHIPS_DIR ||
      "trust_relationships";
    this.identityAccountId = this.cfg.require("identityAccountId");
    const orgAccountIds = this.cfg.getObject<Array<string | number>>("orgAccountId") || [];
    this.orgAccountId = String(orgAccountIds[0] || "").trim();
    if (!this.orgAccountId) {
      throw new Error("Missing required configuration value: orgAccountId");
    }
    this.importExisting =
      args.importExisting ?? this.cfg.getBoolean("importExisting") ?? false;
    this.staticTags =
      this.cfg.getObject<Record<string, string>>("statictags") || {};
    this.payload = this.parsePayload();

    this.iamCatalog =
      this.loadYaml<IAMRolesFile>(
        path.join(this.rolesDir, "iam.yml"),
      ) || {};

    pulumi.log.info("=== AWS IAM Roles deployment starting ===");
    pulumi.log.info(`Target account  : ${this.payload.accountId}`);
    pulumi.log.info(`Identity account: ${this.identityAccountId}`);
    pulumi.log.info(`Import existing : ${this.importExisting}`);

    this.deploy().catch((err) => {
      pulumi.log.error(`❌ Deployment failed: ${err}`);
      throw err;
    });
  }

  // -------------------------------------------------------------------------
  // Config helpers
  // -------------------------------------------------------------------------

  private parsePayload(): ParsedPayload {
    const raw =
      process.env.PAYLOAD ||
      process.env.payload ||
      this.cfg.get("payload");
    if (!raw) {
      throw new Error("Missing PAYLOAD environment variable");
    }

    let parsed: any = raw;
    if (typeof raw === "string") {
      try {
        parsed = JSON.parse(raw);
      } catch {
        parsed = { account_id: raw };
      }
    }

    const accountId = String(
      parsed.account_id ||
        parsed.accountId ||
        parsed.detail?.accountId ||
        parsed.detail?.account_id ||
        raw,
    ).trim();

    return { accountId };
  }

  // -------------------------------------------------------------------------
  // YAML / file helpers
  // -------------------------------------------------------------------------

  private loadYaml<T>(filePath: string): T | undefined {
    if (!fs.existsSync(filePath)) return undefined;
    return yaml.load(fs.readFileSync(filePath, "utf-8")) as T;
  }

  /**
   * Parses the raw YAML list into typed ParsedRole objects.
   *
   * Handles both formats:
   *   - "ROLE-NAME"                               → { roleName, awsManagedPolicies: [] }
   *   - { "ROLE-NAME": ["Policy1", "Policy2"] }  → { roleName, awsManagedPolicies: [...] }
   */
  private parseRoleEntries(entries: RoleEntry[] | undefined): ParsedRole[] {
    if (!entries || !Array.isArray(entries)) return [];

    return entries.map((entry): ParsedRole => {
      if (typeof entry === "string") {
        return { roleName: entry.trim(), awsManagedPolicies: [] };
      }

      const roleName = Object.keys(entry)[0];
      const policies = entry[roleName];
      return {
        roleName: roleName.trim(),
        awsManagedPolicies: Array.isArray(policies)
          ? policies.map((p) => String(p).trim()).filter(Boolean)
          : [],
      };
    });
  }

  private getIamRoles(): ParsedRole[] {
    return this.parseRoleEntries(this.iamCatalog.iam);
  }

  // -------------------------------------------------------------------------
  // Managed-policy ARN resolver
  // -------------------------------------------------------------------------

  private resolveManagedPolicyArn(policyRef: string): string | { type: "customer"; filePath: string; name: string } {
    if (policyRef.startsWith("arn:")) return policyRef;

    // Check customer_managed_policies across ALL role folders before assuming AWS managed
    const cmpBase = path.join("policies", "customer_managed_policies");
    if (fs.existsSync(cmpBase)) {
      for (const roleFolder of fs.readdirSync(cmpBase)) {
        const candidate = path.join(cmpBase, roleFolder, `${policyRef}.json`);
        if (fs.existsSync(candidate)) {
          pulumi.log.info(`Resolved '${policyRef}' as cross-role customer managed policy from ${candidate}`);
          return { type: "customer", filePath: candidate, name: policyRef };
        }
      }
    }

    // AWS managed policy file lookup
    const candidates = [
      path.join("policies", "aws_managed_policies", `${policyRef}.yml`),
      path.join("policies", "aws_managed_policies", `${policyRef}.yaml`),
    ];
    for (const file of candidates) {
      if (!fs.existsSync(file)) continue;
      const doc = yaml.load(fs.readFileSync(file, "utf-8")) as { name?: string; arn?: string } | string;
      if (typeof doc === "string") return doc.startsWith("arn:") ? doc : `arn:aws:iam::aws:policy/${doc}`;
      if (doc?.arn) return doc.arn;
      if (doc?.name) return `arn:aws:iam::aws:policy/${doc.name}`;
    }

    return `arn:aws:iam::aws:policy/${policyRef}`;
  }

  // -------------------------------------------------------------------------
  // Trust-policy helpers
  // -------------------------------------------------------------------------

  private getIdentityTrustPolicy(roleName: string): string {
    const candidates = [
      path.join("policies", "identity-trust", `${roleName}.json`),
      path.join("policies", "identity-trust", `${roleName}.yml`),
      path.join("policies", "identity-trust", `${roleName}.yaml`),
    ];

    for (const file of candidates) {
      if (fs.existsSync(file)) {
        pulumi.log.info(
          `[${this.identityAccountId}] Identity trust policy for '${roleName}' from ${file}`,
        );
        return fs.readFileSync(file, "utf-8");
      }
    }

    return JSON.stringify({
      Version: "2012-10-17",
      Statement: [
        {
          Effect: "Allow",
          Principal: { AWS: `arn:aws:iam::${this.identityAccountId}:root` },
          Action: "sts:AssumeRole",
        },
      ],
    });
  }

  private getTargetTrustPolicy(roleName: string): string {
    const candidates = [
      path.join(this.trustRelationshipsDir, `${roleName}.json`),
      path.join(this.trustRelationshipsDir, "default.json"),
    ];

    for (const file of candidates) {
      if (fs.existsSync(file)) {
        pulumi.log.info(
          `[${this.payload.accountId}] Trust policy for '${roleName}' from ${file}`,
        );
        return fs.readFileSync(file, "utf-8");
      }
    }

    pulumi.log.info(
      `[${this.payload.accountId}] No trust file for '${roleName}'. Using built-in default.`,
    );
    return JSON.stringify({
      Version: "2012-10-17",
      Statement: [
        {
          Effect: "Allow",
          Principal: { AWS: `arn:aws:iam::${this.identityAccountId}:root` },
          Action: "sts:AssumeRole",
        },
      ],
    });
  }

  private getDefaultIdentityAssumePermission(roleName: string): string {
    return JSON.stringify({
      Version: "2012-10-17",
      Statement: [
        {
          Effect: "Allow",
          Action: "sts:AssumeRole",
          Resource: `arn:aws:iam::*:role/${roleName}`,
        },
      ],
    });
  }

  // -------------------------------------------------------------------------
  // Utilities
  // -------------------------------------------------------------------------

  private sanitizeName(value: string): string {
    return value.replace(/[^a-zA-Z0-9+=,.@_-]/g, "-");
  }

  // -------------------------------------------------------------------------
  // Providers
  // -------------------------------------------------------------------------

  private createIdentityProvider(): aws.Provider {
    if (this.identityProvider) return this.identityProvider;
    this.identityProvider = new aws.Provider("prov-identity", {
      region: this.cfg.get("region") || "us-east-1",
    });
    return this.identityProvider;
  }

  private createTargetProvider(accountId: string): aws.Provider {
    const awsCfg = new pulumi.Config("aws");
    const assumeRoles =
      awsCfg.getObject<Array<{ roleArn?: string }>>("assumeRoles") || [];
    const roleArn = assumeRoles[0]?.roleArn;

    if (!roleArn) {
      throw new Error("Missing aws:assumeRoles[0].roleArn configuration");
    }

    pulumi.log.info(`[${accountId}] Target role ARN: ${roleArn}`);

    return new aws.Provider(`prov-${accountId}`, {
      region: awsCfg.get("region") || "us-east-1",
      assumeRoles: [
        {
          roleArn,
          sessionName: `pulumi-${accountId}`,
          externalId: `pulumi-${accountId}`,
        },
      ],
    } as any);
  }

  // -------------------------------------------------------------------------
  // Role creation
  // -------------------------------------------------------------------------

  private async ensureIdentityRole(roleName: string): Promise<aws.iam.Role> {
    if (this.identityRoles[roleName]) return this.identityRoles[roleName];

    const provider = this.createIdentityProvider();
    const opts: pulumi.ResourceOptions & { import?: string } = { provider };

    if (this.importExisting) {
      try {
        await aws.iam.getRole({ name: roleName }, { provider });
        opts.import = roleName;
        pulumi.log.info(
          `[${this.identityAccountId}] Importing existing identity role '${roleName}'`,
        );
      } catch {
        pulumi.log.info(
          `[${this.identityAccountId}] Creating identity role '${roleName}'`,
        );
      }
    }

    const role = new aws.iam.Role(
      `identity-${roleName}`,
      {
        name: roleName,
        assumeRolePolicy: this.getIdentityTrustPolicy(roleName),
        tags: {
          ...this.staticTags,
          Scope: "IAM",
        },
      },
      opts,
    );

    const assumePolicy = new aws.iam.Policy(
      `identity-${roleName}-assume-policy`,
      {
        name: `AssumeRole-${roleName}`,
        policy: this.getDefaultIdentityAssumePermission(roleName),
        tags: {
          ...this.staticTags,
          Scope: "IAM",
          PolicyType: "Identity-AssumeRole",
        },
      },
      { provider, dependsOn: [role] },
    );

    const assumeAttachment = new aws.iam.RolePolicyAttachment(
      `identity-${roleName}-assume-attach`,
      {
        role: role.name,
        policyArn: assumePolicy.arn,
      },
      { provider, dependsOn: [role, assumePolicy] },
    );

    this.deploymentResources.push(role, assumePolicy, assumeAttachment);
    this.identityRoles[roleName] = role;
    return role;
  }

  private async ensureTargetRole(args: {
    roleName: string;
    provider: aws.Provider;
  }): Promise<aws.iam.Role> {
    const { roleName, provider } = args;
    const opts: pulumi.ResourceOptions & { import?: string } = { provider };

    await this.ensureIdentityRole(roleName);

    if (this.importExisting) {
      try {
        await aws.iam.getRole({ name: roleName }, { provider });
        opts.import = roleName;
        pulumi.log.info(`Importing existing role '${roleName}'`);
      } catch {
        pulumi.log.info(`Creating role '${roleName}'`);
      }
    }

    const role = new aws.iam.Role(
      `iam-${roleName}`,
      {
        name: roleName,
        assumeRolePolicy: this.getTargetTrustPolicy(roleName),
        tags: {
          ...this.staticTags,
          Scope: "IAM",
        },
      },
      opts,
    );

    this.deploymentResources.push(role);
    return role;
  }

  // -------------------------------------------------------------------------
  // Policy attachment
  // -------------------------------------------------------------------------

  private async attachManagedPolicies(args: {
    roleName: string;
    role: aws.iam.Role;
    provider: aws.Provider;
    policyRefs: string[];
  }): Promise<void> {
    const { roleName, role, provider, policyRefs } = args;

    if (policyRefs.length === 0) {
      pulumi.log.info(`No AWS managed policies declared for '${roleName}'`);
      return;
    }

    for (const policyRef of policyRefs) {
      const resolved = this.resolveManagedPolicyArn(policyRef);

      if (typeof resolved === "object" && resolved.type === "customer") {
        // Cross-role customer managed policy — create once via cache, attach to any role that references it
        if (!this.customerPolicyCache[resolved.name]) {
          const policy = new aws.iam.Policy(
            `cmp-${this.sanitizeName(resolved.name)}`,
            {
              name: resolved.name,
              policy: fs.readFileSync(resolved.filePath, "utf-8"),
              tags: {
                ...this.staticTags,
                Scope: "IAM",
                PolicyType: "CustomerManaged-CrossRole",
              },
            },
            { provider },
          );

          this.customerPolicyCache[resolved.name] = policy;
          this.deploymentResources.push(policy);
          pulumi.log.info(`Created cross-role customer managed policy '${resolved.name}'`);
        }

        const policy = this.customerPolicyCache[resolved.name];
        const attachment = new aws.iam.RolePolicyAttachment(
          `iam-${roleName}-cmp-${this.sanitizeName(resolved.name)}-attach`,
          { role: role.name, policyArn: policy.arn },
          { provider, dependsOn: [role, policy] },
        );

        this.deploymentResources.push(attachment);
        pulumi.log.info(`Attached cross-role policy '${resolved.name}' to '${roleName}'`);
      } else {
        // AWS managed policy — attach by ARN directly
        const arn = resolved as string;
        const attachment = new aws.iam.RolePolicyAttachment(
          `iam-${roleName}-${this.sanitizeName(policyRef)}-attach`,
          { role: role.name, policyArn: arn },
          { provider, dependsOn: [role] },
        );

        this.deploymentResources.push(attachment);
        pulumi.log.info(`Attached AWS managed policy '${arn}' to '${roleName}'`);
      }
    }
  }

  /**
   * Attaches customer managed policies from:
   *   policies/customer_managed_policies/<ROLE_NAME>/*.json
   */
  private async attachCustomPolicies(args: {
    roleName: string;
    role: aws.iam.Role;
    provider: aws.Provider;
  }): Promise<void> {
    const { roleName, role, provider } = args;

    const roleDir = path.join("policies", "customer_managed_policies", roleName);

    if (!fs.existsSync(roleDir)) {
      pulumi.log.info(`No custom policy folder for '${roleName}' — skipping`);
      return;
    }

    const files = fs.readdirSync(roleDir).filter((f) => f.endsWith(".json"));
    if (files.length === 0) {
      pulumi.log.info(`Custom policy folder exists but has no JSON files for '${roleName}'`);
      return;
    }

    for (const file of files) {
      const policyName = path.basename(file, ".json");
      const policyDoc = fs.readFileSync(path.join(roleDir, file), "utf-8");

      // Register in cache — prevents duplicate resource if another role cross-references this policy
      if (!this.customerPolicyCache[policyName]) {
        const policy = new aws.iam.Policy(
          `iam-${roleName}-${policyName}`,
          {
            name: policyName,
            policy: policyDoc,
            tags: {
              ...this.staticTags,
              Scope: "IAM",
              PolicyType: "IAM-Custom",
            },
          },
          { provider, dependsOn: [role] },
        );

        this.customerPolicyCache[policyName] = policy;
        this.deploymentResources.push(policy);
      }

      const policy = this.customerPolicyCache[policyName];
      const attachment = new aws.iam.RolePolicyAttachment(
        `iam-${roleName}-${policyName}-attach`,
        { role: role.name, policyArn: policy.arn },
        { provider, dependsOn: [role, policy] },
      );

      this.deploymentResources.push(attachment);
      pulumi.log.info(`Attached custom policy '${policyName}' to '${roleName}'`);
    }
  }

  // -------------------------------------------------------------------------
  // Role-set processing
  // -------------------------------------------------------------------------

  private async processRoleSet(
    parsedRoles: ParsedRole[],
    provider: aws.Provider,
  ): Promise<Record<string, aws.iam.Role>> {
    const created: Record<string, aws.iam.Role> = {};

    pulumi.log.info(`Processing ${parsedRoles.length} IAM role(s)`);

    for (const { roleName, awsManagedPolicies } of parsedRoles) {
      const role = await this.ensureTargetRole({ roleName, provider });
      await this.attachManagedPolicies({
        roleName,
        role,
        provider,
        policyRefs: awsManagedPolicies,
      });
      await this.attachCustomPolicies({ roleName, role, provider });
      created[roleName] = role;
    }

    return created;
  }

  // -------------------------------------------------------------------------
  // Entry point
  // -------------------------------------------------------------------------

  private async deploy(): Promise<void> {
    const targetProvider = this.createTargetProvider(this.payload.accountId);

    this.iamRoles = await this.processRoleSet(
      this.getIamRoles(),
      targetProvider,
    );

    const awsCfg = new pulumi.Config("aws");
    const assumeRoles =
      awsCfg.getObject<Array<{ roleArn?: string }>>("assumeRoles") || [];
    const roleArn = assumeRoles[0]?.roleArn;

    if (!roleArn) {
      throw new Error("Missing aws:assumeRoles[0].roleArn configuration");
    }

    new RestoreTrustResource(
      "restore-organization-account-access-role-trust",
      {
        accountId: this.payload.accountId,
        orgAccountId: this.orgAccountId,
        roleArn,
        region: awsCfg.get("region") || "us-east-1",
      },
      {
        parent: this,
        dependsOn: this.deploymentResources,
      },
    );

    this.printSummary();
  }

  private printSummary(): void {
    pulumi.log.info("==================== SUMMARY ====================");
    pulumi.log.info(`IAM roles      : ${Object.keys(this.iamRoles).length}`);
    pulumi.log.info(`Identity roles : ${Object.keys(this.identityRoles).length}`);
    pulumi.log.info("=================================================");
  }
}

// ---------------------------------------------------------------------------
// Stack entry point
// ---------------------------------------------------------------------------

pulumi.log.info("🚀 Starting AWS IAM Roles deployment");
new AWSRolesAndPolicies("aws-roles-policies");