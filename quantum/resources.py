"""Quantum resource estimation for the attack circuits.

Reports the concrete cost of the Shor and Grover circuits this project actually
builds (qubit count, transpiled circuit depth, gate counts), then puts them next
to the *published* estimates for attacking real RSA-2048 — which is the honest way
to show the gap between "runs on a simulator today" and "breaks production crypto".

Run:  python quantum/resources.py
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from qiskit import QuantumCircuit, transpile  # noqa: E402

from quantum.shor import c_amod15, qft_dagger  # noqa: E402


def shor_circuit(a: int = 7, n_count: int = 8) -> QuantumCircuit:
    """The order-finding (QPE) circuit used by shor.py, for N = 15."""
    work = 4
    qc = QuantumCircuit(n_count + work, n_count)
    for q in range(n_count):
        qc.h(q)
    qc.x(n_count)
    for j in range(n_count):
        qc.append(c_amod15(a, 2 ** j), [j] + [n_count + k for k in range(work)])
    qc.append(qft_dagger(n_count), range(n_count))
    qc.measure(range(n_count), range(n_count))
    return qc


def grover_circuit(n: int = 4, iterations: int = 1) -> QuantumCircuit:
    qc = QuantumCircuit(n, n)
    qc.h(range(n))
    for _ in range(iterations):
        qc.h(n - 1); qc.mcx(list(range(n - 1)), n - 1); qc.h(n - 1)        # oracle
        qc.h(range(n)); qc.x(range(n))
        qc.h(n - 1); qc.mcx(list(range(n - 1)), n - 1); qc.h(n - 1)        # diffuser
        qc.x(range(n)); qc.h(range(n))
    qc.measure(range(n), range(n))
    return qc


def estimate(qc: QuantumCircuit) -> dict:
    """Transpile to a hardware-like basis and measure the cost."""
    t = transpile(qc, basis_gates=["u", "cx"], optimization_level=1)
    ops = t.count_ops()
    return {
        "qubits": qc.num_qubits,
        "depth": t.depth(),
        "gates": int(sum(ops.values())),
        "two_qubit_gates": int(ops.get("cx", 0)),
    }


def demo() -> None:
    print("Quantum resource estimation")
    print("=" * 64)

    shor = estimate(shor_circuit())
    grover = estimate(grover_circuit())

    row = "  {:<26} {:>8} {:>8} {:>8} {:>10}"
    print(row.format("circuit", "qubits", "depth", "gates", "2q-gates"))
    print("  " + "-" * 62)
    print(row.format("Shor order-finding (N=15)", shor["qubits"], shor["depth"], shor["gates"], shor["two_qubit_gates"]))
    print(row.format("Grover search (4-bit key)", grover["qubits"], grover["depth"], grover["gates"], grover["two_qubit_gates"]))

    print("\n  Scaling to real targets (published logical-qubit estimates):")
    print("  - RSA-2048 via Shor: ~4,100 logical qubits, ~2^32 Toffoli gates")
    print("    (Gidney & Ekera, 2021: ~20 million noisy physical qubits, ~8 hours).")
    print("  - AES-256 via Grover: ~2^128 iterations even with the quadratic speedup,")
    print("    i.e. still infeasible - which is why AES-256 stays safe.")
    print("\n  Takeaway: the algorithms are exact and run here at small scale; the")
    print("  blocker for real targets is fault-tolerant hardware that does not exist yet.")


if __name__ == "__main__":
    demo()
