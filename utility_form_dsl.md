We need to specify a basic DSL to describe how to generate forms to present to the user so they can enter in their customer details and we can format it correctly to send to the utility.

The utlities table has the following columns:

```python
    name = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text())
    bank_description = db.Column(db.Text(), nullable=False)
```

Here is a proposed format for the `bank_description` column:

```json
[
  {
    "name": "Default Bank (only shown if there are multiple banks)",
    "account_number": "12-1234-1234567-123",
    "fields": [
      {
        "label": "Invoice Number",
        "description": "The invoice number on your bill statement",
        "type": "number",
        "min": 10000,
        "max": 99999,
        "allow_empty": false,
        "target": "particulars"
      },
      {
        "label": "User Name",
        "description": "The user name assocatiated with your account",
        "type": "text",
        "min_chars": 4,
        "allow_empty": false,
        "target": ["code", "reference"]
      }
    ]
  }
]
```
