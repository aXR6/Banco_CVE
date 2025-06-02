# parser.py

import ijson

def parse_item(item: dict) -> tuple:
    """
    Dado um item JSON do NVD, retorna tupla:
    (cve_id, published_date, description, products, operating_systems).
    - cve_id: "CVE_data_meta" → "ID"
    - description: primeira descrição do campo "description_data"
    - products: concat de todos os cpe23Uri sob configurations.nodes
    - operating_systems: concat de cpe23Uri que começam com "cpe:2.3:o:"
    """
    cve = item["cve"]
    cve_id = cve["CVE_data_meta"]["ID"]
    pub = item.get("publishedDate", "")
    desc = cve["description"]["description_data"][0]["value"].replace("\n", " ")
    products = "; ".join(
        cpe.get("cpe23Uri", "")
        for node in item["configurations"]["nodes"]
        for cpe in node.get("cpe_match", [])
    )
    oss = "; ".join(
        uri for node in item["configurations"]["nodes"]
        for cpe in node.get("cpe_match", [])
        if (uri := cpe.get("cpe23Uri", "")).startswith("cpe:2.3:o:")
    )
    return (cve_id, pub, desc, products, oss)
