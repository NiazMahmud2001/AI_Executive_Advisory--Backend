"""Finance calculators for the Finance Advisor: the model chooses a tool and its inputs, Python computes the result."""


class ToolError(ValueError):
    """The inputs do not fit the tool, for example a percentage change from zero."""


def pct_change(old: float, new: float) -> float:
    if old == 0:
        raise ToolError("a change from 0 is not defined")
    return (new - old) / abs(old) * 100


def share(part: float, whole: float) -> float:
    if whole == 0:
        raise ToolError("the whole must not be 0")
    return part / whole * 100


def difference(a: float, b: float) -> float:
    return a - b


def pro_rata(annual: float, months: float) -> float:
    if not 1 <= months <= 12:
        raise ToolError("months must be from 1 to 12")
    return annual * months / 12


# tool name -> (function, formula with the input names as {0} and {1}, whether the result is a percentage)
TOOLS = {
    "pct_change": (pct_change, "({1} − {0}) ÷ {0} × 100", True),  # growth, or spending against a budget
    "share": (share, "{0} ÷ {1} × 100", True),                    # margins, share of a budget used
    "difference": (difference, "{0} − {1}", False),               # amount over or under a budget
    "pro_rata": (pro_rata, "{0} × {1} ÷ 12", False),              # part of an annual amount
}


def show(value: float, percent: bool = False, unit: str = "") -> str:
    """10.04 -> "10.0%"; 4620000 with "AED" -> "AED 4,620,000"."""
    if percent:
        return f"{value:.1f}%"
    text = f"{value:,.0f}" if float(value).is_integer() else f"{value:,.2f}"
    return f"{unit} {text}".strip()
