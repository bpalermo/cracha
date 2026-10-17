package e2e

import (
	"context"
	"fmt"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// The registrar sidecar hands the plugin's socket to kubelet, which then
// lists the driver on the node's CSINode object; without that no inline
// volume of the driver can be published.
func TestDriverRegistersWithKubelet(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	err := eventually(ctx, func() error {
		nodes, err := client.StorageV1().CSINodes().List(ctx, metav1.ListOptions{})
		if err != nil {
			return err
		}
		var names []string
		for _, n := range nodes.Items {
			for _, d := range n.Spec.Drivers {
				if d.Name == driverName {
					return nil
				}
				names = append(names, d.Name)
			}
		}
		return fmt.Errorf("CSINode drivers = %v, want %s among them", names, driverName)
	})
	if err != nil {
		t.Fatal(err)
	}
}
