//go:build ignore

// Этот файл не собирается в составе be3600: он копируется скриптом
// scripts/build-singbox.sh в клон sing-box (cmd/sing-box-slim/), где тег
// ignore срезается и файл становится частью slim-сборки.

package main

// Урезанная замена пакета include: регистрируются только компоненты,
// которые реально использует конфиг be3600 (tun/mixed входы, vless/direct/
// selector/urltest выходы, базовые DNS-транспорты). Всё остальное линкер
// выкидывает из бинарника.

import (
	"context"
	"net"

	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/endpoint"
	"github.com/sagernet/sing-box/adapter/inbound"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/adapter/service"
	"github.com/sagernet/sing-box/common/urltest"
	"github.com/sagernet/sing-box/dns"
	"github.com/sagernet/sing-box/dns/transport"
	"github.com/sagernet/sing-box/dns/transport/hosts"
	"github.com/sagernet/sing-box/dns/transport/local"
	"github.com/sagernet/sing-box/experimental"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/protocol/block"
	"github.com/sagernet/sing-box/protocol/direct"
	protocolDNS "github.com/sagernet/sing-box/protocol/dns"
	"github.com/sagernet/sing-box/protocol/group"
	"github.com/sagernet/sing-box/protocol/mixed"
	"github.com/sagernet/sing-box/protocol/tun"
	"github.com/sagernet/sing-box/protocol/vless"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/observable"
)

func slimContext(ctx context.Context) context.Context {
	return box.Context(ctx, slimInboundRegistry(), slimOutboundRegistry(), endpoint.NewRegistry(), slimDNSTransportRegistry(), service.NewRegistry())
}

func slimInboundRegistry() *inbound.Registry {
	registry := inbound.NewRegistry()
	tun.RegisterInbound(registry)
	mixed.RegisterInbound(registry)
	return registry
}

func slimOutboundRegistry() *outbound.Registry {
	registry := outbound.NewRegistry()
	direct.RegisterOutbound(registry)
	block.RegisterOutbound(registry)
	protocolDNS.RegisterOutbound(registry)
	group.RegisterSelector(registry)
	group.RegisterURLTest(registry)
	vless.RegisterOutbound(registry)
	return registry
}

// Заглушка Clash API для обратной совместимости: на уже установленных
// роутерах config.json ещё содержит experimental.clash_api, а бинарник
// обновляется автоматически при загрузке. Без зарегистрированного
// конструктора box.New падает и sing-box уходит в краш-луп. Заглушка
// принимает такой конфиг и просто не поднимает API-сервер.
func init() {
	experimental.RegisterClashServerConstructor(newClashServerStub)
}

type clashServerStub struct {
	historyStorage adapter.URLTestHistoryStorage
}

func newClashServerStub(ctx context.Context, logFactory log.ObservableFactory, options option.ClashAPIOptions) (adapter.ClashServer, error) {
	logFactory.NewLogger("clash-api").Warn("clash api is not included in this slim build, ignoring experimental.clash_api")
	return &clashServerStub{historyStorage: urltest.NewHistoryStorage()}, nil
}

func (s *clashServerStub) Name() string                                            { return "clash server (stub)" }
func (s *clashServerStub) Start(stage adapter.StartStage) error                    { return nil }
func (s *clashServerStub) Close() error                                            { return nil }
func (s *clashServerStub) Mode() string                                            { return "Rule" }
func (s *clashServerStub) ModeList() []string                                      { return []string{"Rule"} }
func (s *clashServerStub) SetModeUpdateHook(hook *observable.Subscriber[struct{}]) {}
func (s *clashServerStub) HistoryStorage() adapter.URLTestHistoryStorage {
	return s.historyStorage
}

func (s *clashServerStub) RoutedConnection(ctx context.Context, conn net.Conn, metadata adapter.InboundContext, matchedRule adapter.Rule, matchOutbound adapter.Outbound) net.Conn {
	return conn
}

func (s *clashServerStub) RoutedPacketConnection(ctx context.Context, conn N.PacketConn, metadata adapter.InboundContext, matchedRule adapter.Rule, matchOutbound adapter.Outbound) N.PacketConn {
	return conn
}

func slimDNSTransportRegistry() *dns.TransportRegistry {
	registry := dns.NewTransportRegistry()
	transport.RegisterTCP(registry)
	transport.RegisterUDP(registry)
	transport.RegisterTLS(registry)
	transport.RegisterHTTPS(registry)
	hosts.RegisterTransport(registry)
	local.RegisterTransport(registry)
	return registry
}
