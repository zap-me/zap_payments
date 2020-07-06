We need to specify a basic DSL to describe how to generate forms to present to the user so they can enter in their customer details and we can format it correctly to send to the utility.

The utlities table has the following column:

```python
    name = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text())
    bank_account = db.Column(db.String(255), nullable=False)
    fields_description = db.Column(db.Text(), nullable=False)
```

Here is a proposed format for the `fields_description` column:

```json
[
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
    "type": "string",
    "min_chars": 4,
    "allow_empty": false,
    "target": ["code", "reference"]
  }
]
```
