from obli_rca.evaluation.tables import format_ablation, format_cost, format_main_results, markdown_table


def test_markdown_table():
    table = markdown_table(["a", "b"], [[1, 2]])
    assert table.splitlines()[0] == "| a | b |"
    assert "| 1 | 2 |" in table


def test_table_formatters():
    main = format_main_results(
        [
            {
                "group": "All",
                "method": "ObliRCA",
                "n": 102,
                "n_l": 59,
                "f_at_1": 0.8,
                "f_at_3": 0.9,
                "f_at_5": 0.91,
                "l_at_1": 0.5,
                "l_at_3": 0.7,
                "l_at_5": 0.78,
                "mrr_at_10": 0.86,
            }
        ]
    )
    assert "102/59" in main
    assert "0.8619" not in main  # formatter uses four decimals of the input
    assert format_ablation([{"group": "All", "configuration": "x", "f_at_5": 1, "l_at_5": 2, "mrr_at_10": 3}])
    assert format_cost([{"stage": "Online", "component": "SOI", "minutes": 1, "tokens_k": 2}])
