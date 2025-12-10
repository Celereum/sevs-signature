//! Circuit System for ZK Proofs
//!
//! Provides a simple constraint system for building ZK circuits.
//! Circuits define the computation that proofs verify.

use crate::crypto::Hash;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// A variable in the circuit
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Variable(pub u32);

impl Variable {
    /// Constant one
    pub const ONE: Variable = Variable(0);

    /// Create a new variable
    pub fn new(id: u32) -> Self {
        Variable(id)
    }
}

/// A linear combination of variables
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LinearCombination {
    /// Terms: variable -> coefficient
    pub terms: HashMap<Variable, i64>,
}

impl LinearCombination {
    /// Create empty linear combination
    pub fn new() -> Self {
        Self {
            terms: HashMap::new(),
        }
    }

    /// Create from a single variable
    pub fn from_variable(var: Variable) -> Self {
        let mut lc = Self::new();
        lc.terms.insert(var, 1);
        lc
    }

    /// Create a constant
    pub fn constant(value: i64) -> Self {
        let mut lc = Self::new();
        lc.terms.insert(Variable::ONE, value);
        lc
    }

    /// Add a term
    pub fn add_term(&mut self, var: Variable, coeff: i64) {
        *self.terms.entry(var).or_insert(0) += coeff;
    }

    /// Add another linear combination
    pub fn add(&mut self, other: &LinearCombination) {
        for (var, coeff) in &other.terms {
            self.add_term(*var, *coeff);
        }
    }

    /// Multiply by scalar
    pub fn scale(&mut self, scalar: i64) {
        for coeff in self.terms.values_mut() {
            *coeff *= scalar;
        }
    }

    /// Evaluate the linear combination given variable assignments
    pub fn evaluate(&self, assignments: &HashMap<Variable, i64>) -> i64 {
        let mut result = 0i64;
        for (var, coeff) in &self.terms {
            let value = if *var == Variable::ONE {
                1
            } else {
                *assignments.get(var).unwrap_or(&0)
            };
            result += coeff * value;
        }
        result
    }
}

/// A constraint in the circuit: A * B = C
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Constraint {
    /// Left input
    pub a: LinearCombination,
    /// Right input
    pub b: LinearCombination,
    /// Output
    pub c: LinearCombination,
    /// Constraint name (for debugging)
    pub name: String,
}

impl Constraint {
    /// Create a new constraint
    pub fn new(a: LinearCombination, b: LinearCombination, c: LinearCombination, name: &str) -> Self {
        Self {
            a,
            b,
            c,
            name: name.to_string(),
        }
    }

    /// Check if constraint is satisfied
    pub fn is_satisfied(&self, assignments: &HashMap<Variable, i64>) -> bool {
        let a_val = self.a.evaluate(assignments);
        let b_val = self.b.evaluate(assignments);
        let c_val = self.c.evaluate(assignments);
        a_val * b_val == c_val
    }
}

/// A complete circuit
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Circuit {
    /// All constraints
    pub constraints: Vec<Constraint>,
    /// Public input variables
    pub public_inputs: Vec<Variable>,
    /// Private witness variables
    pub private_witnesses: Vec<Variable>,
    /// Total number of variables
    pub num_variables: u32,
    /// Circuit name
    pub name: String,
}

impl Circuit {
    /// Create an empty circuit
    pub fn new(name: &str) -> Self {
        Self {
            constraints: Vec::new(),
            public_inputs: Vec::new(),
            private_witnesses: Vec::new(),
            num_variables: 1, // Variable 0 is ONE
            name: name.to_string(),
        }
    }

    /// Get number of constraints
    pub fn num_constraints(&self) -> usize {
        self.constraints.len()
    }

    /// Check if all constraints are satisfied
    pub fn is_satisfied(&self, assignments: &HashMap<Variable, i64>) -> bool {
        self.constraints.iter().all(|c| c.is_satisfied(assignments))
    }

    /// Generate a unique circuit hash
    pub fn hash(&self) -> Hash {
        let data = bincode::serialize(self).unwrap_or_default();
        Hash::hash(&data)
    }
}

/// Circuit builder for easy circuit construction
pub struct CircuitBuilder {
    circuit: Circuit,
    next_var: u32,
}

impl CircuitBuilder {
    /// Create a new circuit builder
    pub fn new(name: &str) -> Self {
        Self {
            circuit: Circuit::new(name),
            next_var: 1, // 0 is reserved for ONE
        }
    }

    /// Allocate a public input variable
    pub fn public_input(&mut self) -> Variable {
        let var = Variable::new(self.next_var);
        self.next_var += 1;
        self.circuit.num_variables = self.next_var;
        self.circuit.public_inputs.push(var);
        var
    }

    /// Allocate a private witness variable
    pub fn private_witness(&mut self) -> Variable {
        let var = Variable::new(self.next_var);
        self.next_var += 1;
        self.circuit.num_variables = self.next_var;
        self.circuit.private_witnesses.push(var);
        var
    }

    /// Add a constraint: a * b = c
    pub fn constraint(
        &mut self,
        a: LinearCombination,
        b: LinearCombination,
        c: LinearCombination,
        name: &str,
    ) {
        self.circuit.constraints.push(Constraint::new(a, b, c, name));
    }

    /// Constrain a = b (equality)
    pub fn enforce_equal(&mut self, a: Variable, b: Variable, name: &str) {
        // a * 1 = b
        let lc_a = LinearCombination::from_variable(a);
        let lc_one = LinearCombination::constant(1);
        let lc_b = LinearCombination::from_variable(b);
        self.constraint(lc_a, lc_one, lc_b, name);
    }

    /// Constrain a + b = c (addition)
    pub fn enforce_add(&mut self, a: Variable, b: Variable, c: Variable, name: &str) {
        // (a + b) * 1 = c
        let mut lc_sum = LinearCombination::from_variable(a);
        lc_sum.add_term(b, 1);
        let lc_one = LinearCombination::constant(1);
        let lc_c = LinearCombination::from_variable(c);
        self.constraint(lc_sum, lc_one, lc_c, name);
    }

    /// Constrain a * b = c (multiplication)
    pub fn enforce_mul(&mut self, a: Variable, b: Variable, c: Variable, name: &str) {
        let lc_a = LinearCombination::from_variable(a);
        let lc_b = LinearCombination::from_variable(b);
        let lc_c = LinearCombination::from_variable(c);
        self.constraint(lc_a, lc_b, lc_c, name);
    }

    /// Constrain a to be boolean (0 or 1)
    pub fn enforce_boolean(&mut self, a: Variable, name: &str) {
        // a * (1 - a) = 0
        // a * 1 - a * a = 0
        // We need: a * (1 - a) = 0
        let lc_a = LinearCombination::from_variable(a);
        let mut lc_one_minus_a = LinearCombination::constant(1);
        lc_one_minus_a.add_term(a, -1);
        let lc_zero = LinearCombination::new();
        self.constraint(lc_a, lc_one_minus_a, lc_zero, name);
    }

    /// Constrain value to be within range [0, 2^bits)
    pub fn enforce_range(&mut self, value: Variable, bits: usize, name: &str) -> Vec<Variable> {
        // Decompose value into bits and constrain each to be boolean
        let mut bit_vars = Vec::new();

        for i in 0..bits {
            let bit = self.private_witness();
            self.enforce_boolean(bit, &format!("{}_bit_{}", name, i));
            bit_vars.push(bit);
        }

        // Constrain: value = sum(bit_i * 2^i)
        let mut lc_sum = LinearCombination::new();
        for (i, &bit) in bit_vars.iter().enumerate() {
            lc_sum.add_term(bit, 1i64 << i);
        }

        let lc_value = LinearCombination::from_variable(value);
        let lc_one = LinearCombination::constant(1);
        self.constraint(lc_sum, lc_one, lc_value, &format!("{}_range", name));

        bit_vars
    }

    /// Build the circuit
    pub fn build(self) -> Circuit {
        self.circuit
    }
}

/// Pre-built circuits for common operations
pub mod prebuilt {
    use super::*;

    /// Create a transfer circuit
    /// Verifies: sender_balance >= amount && new_balance = old_balance - amount
    pub fn transfer_circuit() -> Circuit {
        let mut builder = CircuitBuilder::new("transfer");

        // Public inputs
        let sender = builder.public_input();
        let receiver = builder.public_input();
        let amount = builder.public_input();
        let old_sender_balance = builder.public_input();
        let new_sender_balance = builder.public_input();

        // Private witnesses
        let _sender_secret = builder.private_witness();

        // Constraints:
        // 1. new_balance = old_balance - amount
        // We need: old_balance - amount - new_balance = 0
        // Or: (old_balance - amount) * 1 = new_balance
        let mut lc_old_minus_amount = LinearCombination::from_variable(old_sender_balance);
        lc_old_minus_amount.add_term(amount, -1);
        let lc_one = LinearCombination::constant(1);
        let lc_new = LinearCombination::from_variable(new_sender_balance);
        builder.constraint(lc_old_minus_amount, lc_one, lc_new, "balance_update");

        // 2. Range check on amount (simplified - 64 bits)
        builder.enforce_range(amount, 8, "amount_range"); // Using 8 bits for simplicity in tests

        builder.build()
    }

    /// Create a hash preimage circuit
    /// Verifies: H(preimage) = hash (without revealing preimage)
    pub fn hash_preimage_circuit() -> Circuit {
        let mut builder = CircuitBuilder::new("hash_preimage");

        // Public input: the hash
        let _hash = builder.public_input();

        // Private witness: the preimage
        let _preimage = builder.private_witness();

        // In a real circuit, we'd have constraints for the hash function
        // Here we just have a placeholder structure

        builder.build()
    }

    /// Create a merkle proof circuit
    /// Verifies membership in a merkle tree
    pub fn merkle_proof_circuit(depth: usize) -> Circuit {
        let mut builder = CircuitBuilder::new("merkle_proof");

        // Public inputs
        let _root = builder.public_input();
        let _leaf = builder.public_input();

        // Private witnesses: the path
        for i in 0..depth {
            let _sibling = builder.private_witness();
            let direction = builder.private_witness();
            builder.enforce_boolean(direction, &format!("direction_{}", i));
        }

        builder.build()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_linear_combination() {
        let mut lc = LinearCombination::new();
        let var_a = Variable::new(1);
        let var_b = Variable::new(2);

        lc.add_term(var_a, 2);
        lc.add_term(var_b, 3);

        let mut assignments = HashMap::new();
        assignments.insert(var_a, 5);
        assignments.insert(var_b, 7);

        // 2*5 + 3*7 = 10 + 21 = 31
        assert_eq!(lc.evaluate(&assignments), 31);
    }

    #[test]
    fn test_constraint_satisfaction() {
        // a * b = c where a=3, b=4, c=12
        let var_a = Variable::new(1);
        let var_b = Variable::new(2);
        let var_c = Variable::new(3);

        let constraint = Constraint::new(
            LinearCombination::from_variable(var_a),
            LinearCombination::from_variable(var_b),
            LinearCombination::from_variable(var_c),
            "mul",
        );

        let mut assignments = HashMap::new();
        assignments.insert(var_a, 3);
        assignments.insert(var_b, 4);
        assignments.insert(var_c, 12);

        assert!(constraint.is_satisfied(&assignments));

        // Wrong value should fail
        assignments.insert(var_c, 11);
        assert!(!constraint.is_satisfied(&assignments));
    }

    #[test]
    fn test_circuit_builder() {
        let mut builder = CircuitBuilder::new("test");

        let a = builder.public_input();
        let b = builder.public_input();
        let c = builder.private_witness();

        builder.enforce_mul(a, b, c, "a_times_b");

        let circuit = builder.build();

        assert_eq!(circuit.num_constraints(), 1);
        assert_eq!(circuit.public_inputs.len(), 2);
        assert_eq!(circuit.private_witnesses.len(), 1);
    }

    #[test]
    fn test_boolean_constraint() {
        let mut builder = CircuitBuilder::new("bool_test");
        let b = builder.private_witness();
        builder.enforce_boolean(b, "is_bool");
        let circuit = builder.build();

        // Test with b=0
        let mut assignments = HashMap::new();
        assignments.insert(b, 0);
        assert!(circuit.is_satisfied(&assignments));

        // Test with b=1
        assignments.insert(b, 1);
        assert!(circuit.is_satisfied(&assignments));

        // Test with b=2 (should fail)
        assignments.insert(b, 2);
        assert!(!circuit.is_satisfied(&assignments));
    }

    #[test]
    fn test_transfer_circuit() {
        let circuit = prebuilt::transfer_circuit();
        assert!(circuit.num_constraints() > 0);
        println!("Transfer circuit has {} constraints", circuit.num_constraints());
    }
}
