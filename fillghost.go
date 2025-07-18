package tls

import (
	"crypto/rand"
	"errors"
	"math/big"
	"sync"
	"time"
)

// FillGhostConfig 配置自动注入的参数
type FillGhostConfig struct {
	MinLen       int           // 最小负载长度
	MaxLen       int           // 最大负载长度
	Interval     time.Duration // 注入包间隔
	InitialDelay time.Duration // 初始延迟
}

// FillGhostController 控制自动注入
type FillGhostController struct {
	c         *Conn
	cfg       FillGhostConfig
	stopCh    chan struct{}
	stoppedCh chan struct{}
	mu        sync.Mutex
	active    bool
}

// NewFillGhostController 构造控制器
func NewFillGhostController(c *Conn, cfg FillGhostConfig) *FillGhostController {
	return &FillGhostController{
		c:         c,
		cfg:       cfg,
		stopCh:    make(chan struct{}),
		stoppedCh: make(chan struct{}),
	}
}

// Start 开始注入
func (fg *FillGhostController) Start() error {
	fg.mu.Lock()
	defer fg.mu.Unlock()
	if fg.active {
		return errors.New("FillGhost already running")
	}
	fg.stopCh = make(chan struct{})
	fg.stoppedCh = make(chan struct{})
	go fg.loop()
	fg.active = true
	return nil
}

// Stop 停止注入
func (fg *FillGhostController) Stop() {
	fg.mu.Lock()
	defer fg.mu.Unlock()
	if fg.active {
		close(fg.stopCh)
		<-fg.stoppedCh
		fg.active = false
	}
}

// loop 内部注入循环
func (fg *FillGhostController) loop() {
	defer close(fg.stoppedCh)
	if fg.cfg.InitialDelay > 0 {
		select {
		case <-time.After(fg.cfg.InitialDelay):
		case <-fg.stopCh:
			return
		}
	}
	for {
		select {
		case <-fg.stopCh:
			return
		default:
		}
		err := fg.injectOne()
		if err != nil {
			// 可以log输出
			return
		}
		if fg.cfg.Interval > 0 {
			select {
			case <-time.After(fg.cfg.Interval):
			case <-fg.stopCh:
				return
			}
		}
	}
}

// injectOne 生成并注入一个包
func (fg *FillGhostController) injectOne() error {
	aead := fg.c.ExportWriteAEAD()
	if aead == nil {
		return errors.New("fillghost: no AEAD cipher")
	}
	seq := fg.c.ExportWriteSeq()
	L, err := cryptoRandInt(fg.cfg.MinLen, fg.cfg.MaxLen)
	if err != nil {
		return err
	}
	payload := make([]byte, L)
	_, err = rand.Read(payload)
	if err != nil {
		return err
	}
	padded := append(payload, byte(0x17))
	header := []byte{0x17, 0x03, 0x03, 0, 0}
	ciphertext := aead.Seal(nil, seq[:], padded, header[:5])
	ln := len(ciphertext)
	header[3] = byte(ln >> 8)
	header[4] = byte(ln)
	record := append(header, ciphertext...)
	if err := fg.c.FillGhostInjectRawRecord(record); err != nil {
		return err
	}
	fg.c.FillGhostIncWriteSeq()
	return nil
}

// cryptoRandInt [min, max] 闭区间
func cryptoRandInt(min, max int) (int, error) {
	if min == max {
		return min, nil
	}
	if min > max {
		return 0, errors.New("fillghost: min > max")
	}
	diff := big.NewInt(int64(max - min + 1))
	n, err := rand.Int(rand.Reader, diff)
	if err != nil {
		return 0, err
	}
	return int(n.Int64()) + min, nil
}
