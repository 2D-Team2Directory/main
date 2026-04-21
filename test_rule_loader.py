from analysis.rule_loader import load_rules, split_rules_by_type


if __name__ == "__main__":
    rules = load_rules()
    print("전체 룰 개수 =", len(rules))

    grouped = split_rules_by_type(rules)
    print("single_event 룰 개수 =", len(grouped["single_event"]))
    print("aggregation 룰 개수 =", len(grouped["aggregation"]))

    print("\naggregation 룰 목록:")
    for rule in grouped["aggregation"]:
        print("-", rule["rule_id"], rule["name"])

    print("\nsingle_event 룰 목록:")
    for rule in grouped["single_event"]:
        print("-", rule["rule_id"], rule["name"])