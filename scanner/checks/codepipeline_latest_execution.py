"""Report the most recent observable pipeline execution outcome."""

from scanner.check import CheckMeta, Scope
from scanner.findings import Pillar, Severity, Status
from scanner.operations import rows

V2_ONLY = True
REGISTRY = {
    "service": "codepipeline",
    "required_actions": ["codepipeline:ListPipelines", "codepipeline:ListPipelineExecutions"],
    "applicability": "Existing CodePipeline pipelines with execution history",
    "evidence_fields": ["pipelineExecutionSummaries[].status"],
    "references": ["https://docs.aws.amazon.com/codepipeline/latest/APIReference/API_ListPipelineExecutions.html"],
}
META = CheckMeta(
    "codepipeline_latest_execution", "Latest CodePipeline execution failed", Pillar.OPERATIONAL_EXCELLENCE,
    Severity.MEDIUM, "AWS::CodePipeline::Pipeline", Scope.REGIONAL,
    "Open the pipeline execution history, inspect the failed action, and verify a new execution after addressing the cause.",
)


def run(ctx):
    pipeline = ctx.client("codepipeline")
    for summary in rows(pipeline, "list_pipelines", "pipelines"):
        name = summary["name"]
        arn = ctx.arn("codepipeline", name)
        executions = pipeline.list_pipeline_executions(pipelineName=name, maxResults=1)["pipelineExecutionSummaries"]
        state = executions[0].get("status") if executions else None
        if state == "Failed":
            yield ctx.finding(META, Status.FAIL, arn, "The most recent execution failed.")
        elif state == "Succeeded":
            yield ctx.finding(META, Status.PASS, arn, "The most recent execution succeeded.")
        else:
            yield ctx.finding(META, Status.UNKNOWN, arn, "The most recent execution has no definitive success or failure outcome.")
