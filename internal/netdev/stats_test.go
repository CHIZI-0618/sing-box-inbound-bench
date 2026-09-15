package netdev

import "testing"

func TestDelta(t *testing.T) {
	delta, err := Delta(Stats{RXBytes: 10, RXPackets: 1, TXBytes: 20, TXPackets: 2}, Stats{RXBytes: 30, RXPackets: 3, TXBytes: 50, TXPackets: 5})
	if err != nil {
		t.Fatal(err)
	}
	if delta.RXBytes != 20 || delta.RXPackets != 2 || delta.TXBytes != 30 || delta.TXPackets != 3 {
		t.Fatalf("delta=%+v", delta)
	}
	if _, err = Delta(Stats{RXBytes: 2}, Stats{RXBytes: 1}); err == nil {
		t.Fatal("accepted decreasing counters")
	}
}
