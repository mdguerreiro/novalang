# Knowledge packs

Versioned YAML files of global facts the engine loads at start-up as active knowledge (each fact still passes the
canary gate). Curated by the security research team; candidates come from what the engine learned:

    python bench/pysastbench.py ... --store learned.db --export-pack candidate.yml   # or sentinel.learn.packs.export_pack

Review each candidate fact (its `learned` block says where it came from, the model's rationale and confidence),
drop the `learned` block, and merge it into a pack here. Format and predicates: sentinel/learn/packs.py.
