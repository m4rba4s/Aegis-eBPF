#!/bin/bash
echo "Monitoring GitHub Actions for Release v4.1.2..."
for i in {1..30}; do
  STATUS=$(curl -s "https://api.github.com/repos/m4rba4s/Aegis-eBPF/actions/runs" | jq -r '.workflow_runs[] | select(.name=="Release" and .head_branch=="v4.1.2") | .status' | head -n1)
  CONCLUSION=$(curl -s "https://api.github.com/repos/m4rba4s/Aegis-eBPF/actions/runs" | jq -r '.workflow_runs[] | select(.name=="Release" and .head_branch=="v4.1.2") | .conclusion' | head -n1)
  if [ "$STATUS" == "completed" ]; then
    echo "Release v4.1.2 Finished! Conclusion: $CONCLUSION"
    exit 0
  fi
  echo "Status: $STATUS... waiting 10s"
  sleep 10
done
echo "Timed out waiting for CI."
