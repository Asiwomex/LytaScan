"""Check whether private ECR repositories prevent image-tag overwrites."""

from collections.abc import Iterator

from scanner.check import CheckContext, CheckMeta, Scope
from scanner.config_inventory import items
from scanner.findings import Finding, Pillar, Severity, Status

V2_ONLY = True
META = CheckMeta(
    "ecr_immutable_tags", "ECR repository allows image-tag overwrites",
    Pillar.SECURITY, Severity.MEDIUM, "AWS::ECR::Repository", Scope.REGIONAL,
    "Use immutable release tags and deploy by digest. Review whether any mutable tag exclusions are necessary.",
)
REGISTRY = {
    "service": "ecr",
    "required_actions": ("ecr:DescribeRepositories",),
    "applicability": "Private Amazon ECR repositories",
    "evidence_fields": ("imageTagMutability",),
    "references": ("https://docs.aws.amazon.com/AmazonECR/latest/userguide/image-tag-mutability.html",),
}


def run(ctx: CheckContext) -> Iterator[Finding]:
    for repository in items(ctx.client("ecr"), "describe_repositories", "repositories"):
        mutability = repository.get("imageTagMutability")
        if mutability == "IMMUTABLE":
            status, description = Status.PASS, "All image tags are immutable."
        elif mutability in {"MUTABLE", "MUTABLE_WITH_EXCLUSION", "IMMUTABLE_WITH_EXCLUSION"}:
            status, description = Status.FAIL, "The repository allows at least some image tags to be overwritten."
        else:
            status, description = Status.UNKNOWN, "AWS did not return a recognized tag mutability setting."
        yield ctx.finding(META, status, repository["repositoryArn"], description)
