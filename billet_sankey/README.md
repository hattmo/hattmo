# billet_tree_map

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
python billet_tree_map/main.py input.csv -o treemap.html
```

Open the generated `sankey.html` in a browser.
