# check gather_and_parse_imports.sh

from pprint import pprint
from graphviz import Digraph
from typing import List
from enum import Enum

import random

INPUT_FILE = "tmp/imports.log"
OUTPUT_FILE = "tmp/imports.gv"

SVG_COLORS = ["aliceblue", "antiquewhite", "aqua", "aquamarine", "azure", "beige", "bisque", "black", "blanchedalmond", "blue", "blueviolet", "brown", "burlywood", "cadetblue", "chartreuse", "chocolate", "coral", "cornflowerblue", "cornsilk", "crimson", "cyan", "deeppink", "deepskyblue", "dimgray", "dimgrey", "dodgerblue", "firebrick", "floralwhite", "forestgreen", "gainsboro", "ghostwhite", "gold", "goldenrod", "gray", "grey", "green", "greenyellow", "honeydew", "hotpink", "indianred", "indigo", "ivory", "khaki", "lavender", "lavenderblush", "lawngreen", "lemonchiffon", "lightblue", "lightcoral", "lightcyan", "lightgoldenrodyellow", "lightgray", "lightgreen", "lightgrey", "lightpink", "lightsalmon", "lightseagreen", "lightskyblue", "lightslategray", "lightslategrey", "lightsteelblue", "lightyellow", "lime", "limegreen", "linen", "magenta", "maroon", "mediumaquamarine", "mediumblue", "mediumorchid", "mediumpurple", "mediumseagreen", "mediumslateblue", "mediumspringgreen", "mediumturquoise", "mediumvioletred", "midnightblue", "mintcream", "mistyrose", "moccasin", "navajowhite", "navy", "oldlace", "olivedrab", "orange", "orangered", "orchid", "palegoldenrod", "palegreen", "paleturquoise", "palevioletred", "papayawhip", "peachpuff", "peru", "pink", "plum", "powderblue", "purple", "red", "rosybrown", "royalblue", "saddlebrown", "salmon", "sandybrown", "seagreen", "seashell", "sienna", "silver", "skyblue", "slateblue", "slategray", "slategrey", "snow", "springgreen", "steelblue", "tan", "teal", "thistle", "tomato", "turquoise", "violet", "wheat", "white", "whitesmoke", "yellow", "yellowgreen"]

class ColorMeaning(Enum):
    BLACK = 1
    SOURCE_NODE = 2  # Color based on source node
    TARGET_NODE = 3
    

# https://stackoverflow.com/questions/16891340/remove-a-prefix-from-a-string/16891418
def remove_prefix(text, prefix):
    if text.startswith(prefix):
        return text[len(prefix):]
    return text  # or whatever


def get_filename_and_import_name(line: str):
    filename, import_name = line.split(":")
    filename = filename.strip()
    import_name = import_name.strip()

    if import_name.startswith("#"):
        return "", ""


    if "from " in import_name:
        import_name = import_name.split("import")[0]

    import_name = import_name.split(" as ")[0]
    import_name = remove_prefix(import_name, "from ")
    import_name = remove_prefix(import_name, "import ")


    filename = filename.replace(".py", "").replace("/", ".").replace(".__init__", "")

    filename = filename.strip()
    import_name = import_name.strip()

    return filename, import_name 


def process_the_names(lines: List[str]) -> dict:
    a = list(filter(lambda x: "import app" in x or "from app" in x ,lines))
    b = {}
    for x in a:
        file_name, import_name = get_filename_and_import_name(x)
        if not file_name:
            continue

        b[file_name] = b.get(file_name, set())
        b[file_name].add(import_name)
        # print(file_name, import_name, sep="\t")

    return b

def create_graph(b: dict, output_filename: str, colormeaning: ColorMeaning = ColorMeaning.SOURCE_NODE):
    dot = Digraph()
    color_map = {}

    random.seed(42) # used for consistency of colors of edges

    for filename in b:
        color_map[filename] = random.choice(SVG_COLORS)
    for filename in b:
        for import_name in b[filename]:
            color_map[import_name] = color_map.get(import_name, random.choice(SVG_COLORS))

    for filename in b:
        dot.node(filename, filename)

    for filename in b:
        for import_name in b[filename]:
            # print(filename, import_name)
            
            color = "black"
            if colormeaning == ColorMeaning.SOURCE_NODE:
                color = color_map[filename]
            elif colormeaning == ColorMeaning.TARGET_NODE:
                color = color_map[import_name]

            dot.edge(filename, import_name, color=color)

    dot.render(output_filename, view=False)

    print(f"Check the output in {output_filename}.pdf")


def main():
    with open(INPUT_FILE, 'r') as f:
        lines = f.readlines()

    b = process_the_names(lines)
    # pprint(b)
    create_graph(b, f'{OUTPUT_FILE}.black', colormeaning=ColorMeaning.BLACK)
    create_graph(b, f'{OUTPUT_FILE}.source_file', colormeaning=ColorMeaning.SOURCE_NODE)
    create_graph(b, f'{OUTPUT_FILE}.imported_file', colormeaning=ColorMeaning.TARGET_NODE)


if __name__ == "__main__":
    main()
