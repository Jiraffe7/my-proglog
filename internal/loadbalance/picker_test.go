package loadbalance_test

import (
	"testing"

	"github.com/Jiraffe7/proglog/internal/loadbalance"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/attributes"
	"google.golang.org/grpc/balancer"
	"google.golang.org/grpc/balancer/base"
	"google.golang.org/grpc/resolver"
)

func TestPickerNoSubConnAvailable(t *testing.T) {
	picker := &loadbalance.Picker{}
	for _, method := range []string{
		"/log.vX.log/Produce",
		"/log.vX.log/Consume",
	} {
		info := balancer.PickInfo{FullMethodName: method}
		result, err := picker.Pick(info)
		require.Equal(t, balancer.ErrNoSubConnAvailable, err)
		require.Nil(t, result.SubConn)
	}
}

func TestPickerProducesToLeader(t *testing.T) {
	picker, subConns := setupTest()
	info := balancer.PickInfo{FullMethodName: "/log.vX.log/Produce"}
	for i := 0; i < 5; i++ {
		gotPick, err := picker.Pick(info)
		require.NoError(t, err)
		require.Equal(t, subConns[0], gotPick.SubConn)
	}
}

func TestPickerConsumesFromFollowers(t *testing.T) {
	picker, subConns := setupTest()
	info := balancer.PickInfo{FullMethodName: "/log.vX.log/Consume"}
	for i := 0; i < 5; i++ {
		pick, err := picker.Pick(info)
		require.NoError(t, err)
		require.Equal(t, subConns[i%2+1], pick.SubConn)
	}
}

func setupTest() (*loadbalance.Picker, []*subConn) {
	var subConns []*subConn
	buildInfo := base.PickerBuildInfo{ReadySCs: make(map[balancer.SubConn]base.SubConnInfo)}
	for i := 0; i < 3; i++ {
		sc := &subConn{}
		addr := resolver.Address{Attributes: attributes.New("is_leader", i == 0)}
		// 0th sub conn is the leader
		sc.UpdateAddresses([]resolver.Address{addr})
		buildInfo.ReadySCs[sc] = base.SubConnInfo{Address: addr}
		subConns = append(subConns, sc)
	}
	picker := &loadbalance.Picker{}
	picker.Build(buildInfo)
	return picker, subConns
}

var _ balancer.SubConn = (*subConn)(nil)

type subConn struct {
	addrs []resolver.Address
}

// Connect implements balancer.SubConn
func (*subConn) Connect() {
	panic("unimplemented")
}

// UpdateAddresses implements balancer.SubConn
func (s *subConn) UpdateAddresses(addrs []resolver.Address) {
	s.addrs = addrs
}
