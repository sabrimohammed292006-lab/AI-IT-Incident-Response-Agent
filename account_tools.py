"""Kept for backward compatibility. The real code now lives in it_support/check_tools.py."""

from it_support.check_tools import check_account_status, check_account_status_tool  # noqa: F401

if __name__ == "__main__":
    print(check_account_status("EMP002"))
