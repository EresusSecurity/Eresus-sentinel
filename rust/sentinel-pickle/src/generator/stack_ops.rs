// generator/stack_ops.rs — Stack cleanup for STOP opcode
//
// Before emitting STOP, the stack must contain exactly one item
// (no marks). This module reduces the stack to that state.

use super::Generator;
use super::state::GenStackValue;

impl Generator {
    /// Reduce the stack to exactly one non-mark item so STOP is valid.
    pub(super) fn cleanup_for_stop(&mut self) {
        // Phase 1: collapse all marks into tuples
        while self.has_mark() {
            // Find topmost mark
            if let Some(mark_idx) = self.topmost_mark_idx() {
                let items_above = self.stack.len() - mark_idx - 1;
                if items_above == 0 {
                    // Empty mark → emit EMPTY_TUPLE and replace mark
                    self.output.push(b')'); // EMPTY_TUPLE
                    self.stack.remove(mark_idx);
                    self.push(GenStackValue::Tuple);
                } else {
                    // Items above mark → emit TUPLE to consume mark + items
                    self.output.push(b't'); // TUPLE
                    self.pop_to_mark();
                    self.push(GenStackValue::Tuple);
                }
                self.opcode_count += 1;
            } else {
                break;
            }
        }

        // Phase 2: if stack is empty, push None
        if self.stack.is_empty() {
            self.output.push(b'N'); // NONE
            self.push(GenStackValue::None);
            self.opcode_count += 1;
        }

        // Phase 3: reduce multiple items to a single tuple
        while self.stack.len() > 1 {
            // Pop one item (consumed by the container)
            let depth = self.stack.len();
            if depth == 2 {
                self.output.push(0x86); // TUPLE2
                self.pop(); self.pop();
                self.push(GenStackValue::Tuple);
            } else if depth == 3 {
                self.output.push(0x87); // TUPLE3
                self.pop(); self.pop(); self.pop();
                self.push(GenStackValue::Tuple);
            } else {
                // For deeper stacks, pop one item at a time
                self.output.push(b'0'); // POP
                self.pop();
            }
            self.opcode_count += 1;
        }
    }

    /// Estimate the number of cleanup opcodes needed.
    pub(super) fn estimated_cleanup_cost(&self) -> usize {
        let mut cost = 0;

        // Count marks (each needs 1 opcode to resolve)
        let mark_count = self.stack.iter()
            .filter(|v| matches!(v, GenStackValue::Mark))
            .count();
        cost += mark_count;

        // Count non-mark items
        let item_count = self.stack.len() - mark_count;

        // Need to reduce to 1 item
        if item_count == 0 {
            cost += 1; // Push None
        } else if item_count > 1 {
            cost += item_count - 1; // POP or TUPLE to reduce
        }

        cost
    }
}
