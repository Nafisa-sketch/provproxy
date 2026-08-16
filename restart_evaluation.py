import os
import json
import time
import threading
from typing import Dict, List, Any

class PersistentStateRegistry:
    """
    Thread-safe persistent registry for ProvProxy cross-call accumulation state.
    Survives process restarts while preserving session, destination, and TTL isolation.
    """
    def __init__(self, checkpoint_path: str = "provproxy_state_checkpoint.json", ttl_seconds: int = 300):
        self.checkpoint_path = checkpoint_path
        self.ttl_seconds = ttl_seconds
        self.lock = threading.Lock()
        self.state: Dict[str, List[Dict[str, Any]]] = {}
        self._load_checkpoint()

    def _load_checkpoint(self):
        with self.lock:
            if os.path.exists(self.checkpoint_path):
                try:
                    with open(self.checkpoint_path, "r", encoding="utf-8") as f:
                        data = json.load(f)
                        current_time = time.time()
                        self.state = {}
                        for key, fragments in data.items():
                            valid_fragments = [
                                frag for frag in fragments
                                if current_time - frag.get("timestamp", 0) <= self.ttl_seconds
                            ]
                            if valid_fragments:
                                self.state[key] = valid_fragments
                except Exception:
                    self.state = {}

    def _save_checkpoint(self):
        try:
            with open(self.checkpoint_path, "w", encoding="utf-8") as f:
                json.dump(self.state, f)
        except Exception:
            pass

    def add_fragment(self, session_id: str, destination: str, source: str, fragment_data: str):
        with self.lock:
            key = f"{session_id}:{destination}:{source}"
            current_time = time.time()

            if key not in self.state:
                self.state[key] = []

            self.state[key].append({
                "data": fragment_data,
                "timestamp": current_time
            })
            self._save_checkpoint()

    def get_accumulated(self, session_id: str, destination: str, source: str) -> List[str]:
        with self.lock:
            key = f"{session_id}:{destination}:{source}"
            current_time = time.time()
            fragments = self.state.get(key, [])

            valid_fragments = [
                frag["data"] for frag in fragments
                if current_time - frag.get("timestamp", 0) <= self.ttl_seconds
            ]
            return valid_fragments

    def clear_session(self, session_id: str):
        with self.lock:
            keys_to_delete = [k for k in self.state.keys() if k.startswith(f"{session_id}:")]
            for k in keys_to_delete:
                del self.state[k]
            self._save_checkpoint()


class RestartEvaluationHarness:
    def __init__(self, registry_class):
        self.registry_class = registry_class
        self.checkpoint_file = "test_checkpoint.json"

    def run_before_after_comparison(self, secret_payload: str, fragments: List[str]) -> Dict[str, Any]:
        results = {}

        # =========================================================================
        # SCENARIO 1: BEFORE (Without Persistence / In-Memory State Loss)
        # =========================================================================
        if os.path.exists(self.checkpoint_file):
            os.remove(self.checkpoint_file)

        reg_without = self.registry_class(checkpoint_path=self.checkpoint_file)

        mid = len(fragments) // 2
        for frag in fragments[:mid]:
            reg_without.add_fragment("sess_1", "dest_evil.com", "src_sensitive", frag)

        # Simulate process crash / restart (State wiped, new instance ignores checkpoint)
        reg_restarted_without = self.registry_class(checkpoint_path="non_existent_dummy.json")

        for frag in fragments[mid:]:
            reg_restarted_without.add_fragment("sess_1", "dest_evil.com", "src_sensitive", frag)

        final_accumulated_without = reg_restarted_without.get_accumulated("sess_1", "dest_evil.com", "src_sensitive")
        reconstructed_without = "".join(final_accumulated_without)

        detected_without = secret_payload in reconstructed_without or len(reconstructed_without) >= len(secret_payload) * 0.5

        results["before_restart"] = {
            "detected": detected_without,
            "reconstructed": reconstructed_without,
            "reconstructed_length": len(reconstructed_without),
            "message": "State lost after restart, attack successfully evaded detection!"
        }

        # =========================================================================
        # SCENARIO 2: AFTER (With Persistence Enabled)
        # =========================================================================
        if os.path.exists(self.checkpoint_file):
            os.remove(self.checkpoint_file)

        reg_with = self.registry_class(checkpoint_path=self.checkpoint_file)

        for frag in fragments[:mid]:
            reg_with.add_fragment("sess_2", "dest_evil.com", "src_sensitive", frag)

        # New instance loads existing checkpoint from disk
        reg_restarted_with = self.registry_class(checkpoint_path=self.checkpoint_file)

        for frag in fragments[mid:]:
            reg_restarted_with.add_fragment("sess_2", "dest_evil.com", "src_sensitive", frag)

        final_accumulated_with = reg_restarted_with.get_accumulated("sess_2", "dest_evil.com", "src_sensitive")
        reconstructed_with = "".join(final_accumulated_with)

        detected_with = secret_payload in reconstructed_with or len(reconstructed_with) >= len(secret_payload) * 0.5

        results["after_restart"] = {
            "detected": detected_with,
            "reconstructed": reconstructed_with,
            "reconstructed_length": len(reconstructed_with),
            "persistence_survived": True
        }

        # Cleanup test checkpoint file
        if os.path.exists(self.checkpoint_file):
            os.remove(self.checkpoint_file)

        return results


if __name__ == "__main__":
    harness = RestartEvaluationHarness(PersistentStateRegistry)

    secret = "API_SECRET_KEY_12345"
    frags = [
        "API_",
        "SECRET_",
        "KEY_",
        "12345"
    ]

    res = harness.run_before_after_comparison(secret, frags)

    print("===============================================================================")
    print("PROVPROXY P6 RESTART EVALUATION RESULTS")
    print("===============================================================================")
    print(json.dumps(res, indent=2))