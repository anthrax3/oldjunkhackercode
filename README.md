# JunkHacker: A static analysis security tool for Python applications

Using it like a user:

  `python -m junkhacker.cli -vvv -r tests/files_to_test_against/dir1/`

Using it like a user with debug mode:

  `python -m junkhacker.cli -vvv -d -r tests/files_to_test_against/dir1/`

Running tests from the tests/ directory:

  `python -m pytest test_intra_problems.py::test_path_explosion3`


Current output just looks like
  HERE self.file_summaries is

```json
{
      "tests/files_to_test_against/dir1/plainOpenRedirect.py": [
          {
              "arg": "c.next",
              "lineno": 10,
              "sink": "self.redirect"
          },
          {
              "arg": "c.tboo",
              "lineno": 12,
              "sink": "self.redirect"
          }
      ],
      "tests/files_to_test_against/dir1/through_arg.py": [
          {
              "arg": "bop",
              "lineno": 8,
              "sink": "self.redirect"
          }
      ]
  }
```

# Acknowledgements

[equip](https://github.com/neuroo/equip) for being 90% of this code

[byterun](https://github.com/nedbat/byterun) for being 10% of this code
