The account-role tree (design 6.2 and 6.6): one Account document, whose
role every grant of the account is issued on unless it names its own, and
whose access table makes the implicit grants the Access documents fill.
The grant payments-ledger is written the short way, on the account role
inside the account's envelope; legacy-batch keeps a dedicated shape role,
the override. Compiled, it is testdata/golden/accounts-*.json.
