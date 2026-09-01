# Microsoft Defender for Cloud connectors are configured completely

Microsoft Defender for Cloud uses security connector resources to onboard non-Azure cloud, DevOps, and container registry environments. An incomplete connector can leave assets and recommendations outside Defender for Cloud even though the environment appears to be onboarded.

This check inventories `Microsoft.Security/securityConnectors` resources and verifies that each discovered connector identifies its environment hierarchy and has at least one Defender offering configured. Review the inventory against the environments your organization expects to protect, including AWS, GCP, Azure DevOps, GitHub, GitLab, Docker Hub, and JFrog.

## Remediation actions

- Review each environment in Microsoft Defender for Cloud **Environment settings**.
- Repair connectors with missing hierarchy information or no configured offerings.
- Remove obsolete connectors and onboard expected environments that are absent from the inventory.
- Verify that the assessment account has Reader access to every subscription that owns a connector.

## Learn more

- [Connect cloud environments in Microsoft Defender for Cloud](https://learn.microsoft.com/azure/defender-for-cloud/connect-cloud-to-defender-for-cloud)
- [Overview of Defender for Cloud DevOps security](https://learn.microsoft.com/azure/defender-for-cloud/defender-for-devops-introduction)
- [Multicloud workload protection support](https://learn.microsoft.com/azure/defender-for-cloud/multicloud-support-matrix)
