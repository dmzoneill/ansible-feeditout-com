# PrometheusRuleEvalFailure

## Description

Prometheus is failing to evaluate one or more alerting or recording rules. This means alerts may not fire when they should, and recording rules may produce stale or missing data, creating gaps in monitoring coverage.

## Severity

**Warning**

## Possible Causes

- PromQL syntax error in a rule file (after a recent change)
- Rule references a metric that no longer exists (target removed or renamed)
- Query timeout due to high cardinality or expensive query
- Prometheus overloaded (insufficient CPU/memory for rule evaluation)
- Corrupted or invalid rule file (YAML syntax error)
- Rule group evaluation interval too short for the query complexity

## Investigation

```bash
# Check Prometheus rule evaluation metrics
curl -s http://localhost:9090/api/v1/query?query=prometheus_rule_evaluation_failures_total | python3 -m json.tool

# Check which rule groups have errors
curl -s http://localhost:9090/api/v1/rules | python3 -c "
import json,sys
data=json.load(sys.stdin)
for g in data.get('data',{}).get('groups',[]):
  for r in g.get('rules',[]):
    if r.get('lastError'):
      print(f\"Group: {g['name']}, Rule: {r.get('name','?')}, Error: {r['lastError']}\")" 2>/dev/null

# Check Prometheus logs for rule evaluation errors
journalctl -u prometheus --since "1 hour ago" --no-pager | grep -iE "rule|eval|error"

# Validate all rule files
promtool check rules /etc/prometheus/rules/*.yml

# Check Prometheus resource usage
systemctl status prometheus
ps aux | grep prometheus

# Check rule evaluation duration
curl -s 'http://localhost:9090/api/v1/query?query=prometheus_rule_group_last_duration_seconds' | python3 -m json.tool

# Check TSDB status for cardinality issues
curl -s http://localhost:9090/api/v1/status/tsdb | python3 -m json.tool | head -30
```

## Resolution

1. **If syntax error**, fix the rule file:
   ```bash
   # Identify the error
   promtool check rules /etc/prometheus/rules/*.yml

   # Fix the file
   vim /etc/prometheus/rules/<file>.yml

   # Validate again
   promtool check rules /etc/prometheus/rules/<file>.yml
   ```

2. **Reload Prometheus** to pick up the fix:
   ```bash
   systemctl reload prometheus
   # or
   curl -X POST http://localhost:9090/-/reload
   ```

3. **If query timeout**, optimize the rule:
   - Use recording rules to pre-compute expensive queries
   - Reduce label cardinality
   - Increase `evaluation_interval` for the rule group

4. **If metric no longer exists**, update or remove the rule referencing it.

5. **If Prometheus is overloaded**, check resource consumption and consider:
   - Increasing memory/CPU allocation
   - Reducing scrape targets or scrape frequency
   - Using recording rules to reduce query-time computation

## Prevention

- Always run `promtool check rules` before deploying rule changes
- Use CI/CD validation for Prometheus rule files
- Monitor `prometheus_rule_evaluation_failures_total` and `prometheus_rule_group_last_duration_seconds`
- Keep rule evaluation intervals reasonable (not shorter than scrape intervals)
- Use recording rules for complex aggregations used by multiple alerts
- Review high-cardinality metrics periodically
