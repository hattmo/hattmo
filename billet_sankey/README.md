# billet_sankey

Generate a Sankey diagram from a CSV with these columns:

- `Unit`
- `Office`
- `Workrole`

The diagram flows left-to-right:

- `Unit` on the left
- `Office` split into prefix levels in the middle
- `Workrole` on the right

## Usage

```bash
python billet_sankey/main.py input.csv -o sankey.html
```

Open the generated `sankey.html` in a browser.
