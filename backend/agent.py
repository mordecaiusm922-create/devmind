from backend.agent import DevMindAgent

agent = DevMindAgent()
result = agent.analyze(pr_data)
print(result["summary"]["risk_note"])