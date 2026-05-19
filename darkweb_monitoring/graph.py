from .models import GraphEdge, GraphNode, Indicator, IntelligenceGraph, InvestigationReport


def build_graph(reports: list[InvestigationReport]) -> IntelligenceGraph:
    nodes: dict[str, GraphNode] = {}
    edges: list[GraphEdge] = []
    for report in reports:
        report_node_id = f"investigation:{report.id}"
        nodes[report_node_id] = GraphNode(
            id=report_node_id,
            label=report.title,
            kind="investigation",
            properties={"risk_score": report.risk_score, "focus": report.focus.value},
        )
        for indicator in report.indicators:
            node_id = _indicator_node_id(indicator)
            nodes.setdefault(
                node_id,
                GraphNode(
                    id=node_id,
                    label=indicator.value,
                    kind=indicator.kind,
                    properties={"evidence": indicator.evidence},
                ),
            )
            edges.append(
                GraphEdge(
                    source=report_node_id,
                    target=node_id,
                    relationship="mentions",
                    confidence=indicator.confidence,
                )
            )
    return IntelligenceGraph(nodes=list(nodes.values()), edges=edges)


def _indicator_node_id(indicator: Indicator) -> str:
    normalized = indicator.value.lower().replace(" ", "_")
    return f"{indicator.kind}:{normalized}"

