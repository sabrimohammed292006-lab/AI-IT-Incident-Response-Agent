"""search_it_knowledge: searches the approved IT knowledge base.

Simple keyword scoring (no external services), so results are predictable
and easy to explain in the demo. Agents may only recommend steps that come
from these articles or from tool results.
"""

from __future__ import annotations

import re

from pydantic import BaseModel, Field

from .check_tools import make_agent_tool, safe_tool
from .data_store import DataUnavailableError, load_json
from .schemas import BaseToolResult, Category, ToolError

KNOWLEDGE_FILE = "it_knowledge.json"
MAX_QUERY_LENGTH = 300
MAX_RESULTS = 3
VALID_CATEGORIES = {"account", "vpn", "device", "network", "security", "other"}


class KnowledgeArticle(BaseModel):
    id: str
    title: str
    category: Category
    steps: list[str]
    requires_it_staff: bool
    score: int


class KnowledgeSearchResult(BaseToolResult):
    tool: str = "search_it_knowledge"
    query: str | None = None
    articles: list[KnowledgeArticle] = Field(default_factory=list)


MIN_SCORE = 2  # below this, a match is too weak to trust

_WORD = re.compile(r"[\w؀-ۿ]+")
_STOPWORDS = {
    "the", "is", "my", "a", "an", "and", "or", "to", "of", "in", "on", "it", "i", "me",
    "not", "after", "with", "for", "are", "be", "this", "that", "see", "sees", "user",
    "keeps", "then", "but", "very", "can", "cannot", "does", "do", "has", "have", "from",
    "في", "من", "على", "مش", "عندي",
}


def _tokens(text: str) -> set[str]:
    return {w for w in _WORD.findall(text.lower()) if len(w) > 1 and w not in _STOPWORDS}


def _score(article: dict, query: str, query_tokens: set[str]) -> int:
    score = 0
    q = query.lower()
    for keyword in article["keywords"]:
        kw = keyword.lower()
        if kw in q:  # whole keyword/phrase appears in the query
            score += 3 + kw.count(" ")
    text_tokens = _tokens(article["title"] + " " + article["symptoms"])
    score += len(query_tokens & text_tokens)
    return score


@safe_tool(KnowledgeSearchResult)
def search_it_knowledge(query: str, category: str | None = None) -> dict:
    """Search the approved IT knowledge base for fixes to a problem.

    Only recommend steps that appear in the returned articles.

    Args:
        query: Short description of the problem, for example "vpn certificate expired".
        category: Optional filter: account, vpn, device, network, security or other.
    """
    if not isinstance(query, str) or not query.strip():
        return KnowledgeSearchResult(
            success=False, error=ToolError(code="INVALID_INPUT", message="Query must not be empty.")
        ).model_dump()
    query = query.strip()
    if len(query) > MAX_QUERY_LENGTH:
        return KnowledgeSearchResult(
            success=False,
            error=ToolError(code="INVALID_INPUT",
                            message=f"Query is too long (max {MAX_QUERY_LENGTH} characters)."),
        ).model_dump()

    cat = category.strip().lower() if isinstance(category, str) and category.strip() else None
    if cat is not None and cat not in VALID_CATEGORIES:
        return KnowledgeSearchResult(
            success=False, query=query,
            error=ToolError(code="INVALID_INPUT", message=f"Unknown category '{category}'."),
        ).model_dump()

    try:
        articles = load_json(KNOWLEDGE_FILE)["articles"]
    except (DataUnavailableError, KeyError):
        return KnowledgeSearchResult(
            success=False, query=query,
            error=ToolError(code="DATA_UNAVAILABLE", message="Knowledge base is unavailable."),
        ).model_dump()

    query_tokens = _tokens(query)
    scored = []
    for art in articles:
        if cat and art["category"] != cat:
            continue
        s = _score(art, query, query_tokens)
        if s >= MIN_SCORE:
            scored.append((s, art))
    scored.sort(key=lambda pair: (-pair[0], pair[1]["id"]))

    if not scored:
        return KnowledgeSearchResult(
            success=False, query=query,
            error=ToolError(code="NOT_FOUND",
                            message="No approved fix found. Escalate to IT instead of guessing."),
        ).model_dump()

    return KnowledgeSearchResult(
        success=True,
        query=query,
        articles=[
            KnowledgeArticle(id=a["id"], title=a["title"], category=a["category"],
                             steps=a["steps"], requires_it_staff=a["requires_it_staff"], score=s)
            for s, a in scored[:MAX_RESULTS]
        ],
    ).model_dump()


search_it_knowledge_tool = make_agent_tool(search_it_knowledge)


if __name__ == "__main__":
    import json

    for q in ["my account is locked", "vpn certificate expired", "النت فاصل", "my coffee is cold"]:
        print(q, "->", json.dumps(search_it_knowledge(q), ensure_ascii=False)[:300])
