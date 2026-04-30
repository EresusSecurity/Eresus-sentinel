// generator/core.rs — Main generation loop
//
// Implements generate_internal() which:
// 1. Emits PROTO opcode (for version >= 2)
// 2. Optionally emits FRAME (for version >= 4)
// 3. Loops: pick valid opcode, emit, check budget
// 4. Cleanup stack for STOP
// 5. Emit STOP

use super::Generator;
use super::source::{EntropySource, GenerationSource};

impl Generator {
    /// Internal generation entry-point.
    pub(super) fn generate_internal(
        &mut self,
        source: &mut GenerationSource,
    ) -> Result<Vec<u8>, String> {
        // Emit PROTO for version >= 2
        if self.version >= 2 {
            self.output.push(0x80); // PROTO
            self.output.push(self.version);
            self.opcode_count += 1;
        }

        // Optionally emit FRAME for version >= 4
        let frame_position = if self.version >= 4 && source.gen_bool() {
            let pos = self.output.len();
            // Reserve 9 bytes: 1 opcode + 8 size
            self.output.extend_from_slice(&[0u8; 9]);
            self.opcode_count += 1;
            Some(pos)
        } else {
            None
        };

        // Choose target opcode count
        let (min_ops, max_ops) = self.normalized_opcode_range();
        let target = if min_ops == max_ops {
            max_ops
        } else {
            source.gen_range(min_ops, max_ops + 1)
        };

        // Main generation loop
        let mut body_ops = 0;
        while body_ops + self.estimated_cleanup_cost() < target {
            let valid_ops = self.get_valid_opcodes();
            if valid_ops.is_empty() {
                break;
            }

            // Filter by budget: only opcodes whose cleanup cost fits
            let remaining = target.saturating_sub(body_ops);
            let budgeted: Vec<_> = valid_ops.into_iter()
                .filter(|_| self.estimated_cleanup_cost() + 1 < remaining)
                .collect();
            if budgeted.is_empty() {
                break;
            }

            let chosen = self.weighted_choice(&budgeted, source);
            self.emit_and_process(chosen, source);
            body_ops += 1;

            // Safety: bail if we've produced too many opcodes
            if self.opcode_count > 50_000 {
                break;
            }
        }

        // Cleanup stack to exactly 1 item
        self.cleanup_for_stop();

        // Emit STOP
        self.output.push(b'.'); // STOP
        self.opcode_count += 1;

        // Fill in FRAME size if we reserved space
        if let Some(pos) = frame_position {
            let frame_size = self.output.len().saturating_sub(pos + 9);
            self.output[pos] = 0x95; // FRAME opcode
            self.output[pos + 1..pos + 9]
                .copy_from_slice(&(frame_size as u64).to_le_bytes());
        }

        Ok(self.output.clone())
    }
}
