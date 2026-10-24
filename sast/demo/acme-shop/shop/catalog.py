"""Catalog queries."""
from acme_common.db import run_query


def build_search_sql(term):
    return "SELECT id, title FROM products WHERE title LIKE '%" + term + "%'"


def search_products(term):
    sql = build_search_sql(term.strip())
    return run_query(sql)


def product_rows(where_clause):
    return run_query("SELECT * FROM products WHERE " + where_clause)
