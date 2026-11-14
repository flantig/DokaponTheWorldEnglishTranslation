package main

import "fmt"

// probeCheckpointIntervals reproduces the pinned runner's Python integer-seeded
// MT19937 randint(3600,10800) prefix. uint64 is an explicit supported seed subset;
// zero has one zero limb. The API deliberately exposes no general PRNG state.
func probeCheckpointIntervals(seed uint64, count int) ([]int, error) {
	if count < 0 || count > 4096 {
		return nil, fmt.Errorf("checkpoint schedule count outside0..4096")
	}
	key := []uint32{uint32(seed)}
	if seed>>32 != 0 {
		key = append(key, uint32(seed>>32))
	}
	var state [624]uint32
	state[0] = 19650218
	for index := 1; index < len(state); index++ {
		state[index] = 1812433253*(state[index-1]^(state[index-1]>>30)) + uint32(index)
	}
	index, limb := 1, 0
	for step := 0; step < 624; step++ {
		state[index] = (state[index] ^ ((state[index-1] ^ (state[index-1] >> 30)) * 1664525)) + key[limb] + uint32(limb)
		index++
		limb++
		if index == 624 {
			state[0] = state[623]
			index = 1
		}
		if limb == len(key) {
			limb = 0
		}
	}
	for step := 0; step < 623; step++ {
		state[index] = (state[index] ^ ((state[index-1] ^ (state[index-1] >> 30)) * 1566083941)) - uint32(index)
		index++
		if index == 624 {
			state[0] = state[623]
			index = 1
		}
	}
	state[0] = 0x80000000
	index = 624
	intervals := make([]int, 0, count)
	for draws := 0; len(intervals) < count; draws++ {
		if draws >= 1<<20 {
			return nil, fmt.Errorf("checkpoint schedule rejection work limit")
		}
		if index == 624 {
			for position := 0; position < 624; position++ {
				combined := (state[position] & 0x80000000) | (state[(position+1)%624] & 0x7fffffff)
				state[position] = state[(position+397)%624] ^ (combined >> 1)
				if combined&1 != 0 {
					state[position] ^= 0x9908b0df
				}
			}
			index = 0
		}
		word := state[index]
		index++
		word ^= word >> 11
		word ^= (word << 7) & 0x9d2c5680
		word ^= (word << 15) & 0xefc60000
		word ^= word >> 18
		value := word >> 19
		if value < 7201 {
			intervals = append(intervals, 3600+int(value))
		}
	}
	return intervals, nil
}
