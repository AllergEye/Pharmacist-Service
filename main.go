package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"syscall"

	kitgrpc "github.com/go-kit/kit/transport/grpc"
	"github.com/go-kit/log"
	"github.com/joho/godotenv"
	"github.com/oklog/oklog/pkg/group"
	"github.com/reezanvisram/allergeye/pharmacist/pb"
	"github.com/reezanvisram/allergeye/pharmacist/pkg/auth"
	"github.com/reezanvisram/allergeye/pharmacist/pkg/auth/database"
	"github.com/reezanvisram/allergeye/pharmacist/pkg/auth/database/models"
	"github.com/reezanvisram/allergeye/pharmacist/pkg/auth/lib"
	"google.golang.org/grpc"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
)

func main() {
	var logger log.Logger
	{
		logger = log.NewJSONLogger(os.Stderr)
		logger = log.With(logger, "ts", log.DefaultTimestamp)
		logger = log.With(logger, "caller", log.DefaultCaller)
	}

	if os.Getenv("ENVIRONMENT") != "prod" {
		err := godotenv.Load()
		if err != nil {
			logger.Log("could not load .env file")
			os.Exit(1)
		}
	}

	dsn := fmt.Sprintf("%v:%v@tcp(%v:%v)/%v?parseTime=true", os.Getenv("DB_USER"), os.Getenv("DB_PASSWORD"), os.Getenv("DB_HOST"), os.Getenv("DB_PORT"), os.Getenv("DB_DATABASE"))
	if os.Getenv("ENVIRONMENT") == "prod" {
		dsn = fmt.Sprintf("%v:%v@unix(%v)/%v?parseTime=true", os.Getenv("DB_USER"), os.Getenv("DB_PASSWORD"), os.Getenv("DB_UNIX_SOCKET"), os.Getenv("DB_DATABASE"))
	}

	db, err := gorm.Open(mysql.Open(dsn), &gorm.Config{})
	if err != nil {
		logger.Log("could not connect to database at", dsn)
		os.Exit(1)
	}

	db.AutoMigrate(&models.User{}, &models.RefreshToken{})
	userRepo := database.NewUserRepository(db)
	tokenRepo := database.NewTokenRepository(db)
	helpers := lib.NewHelpers()

	fs := flag.NewFlagSet("pharmacist", flag.ExitOnError)
	grpcAddr := fs.String("grpc-addr", ":8080", "grpc listen address")
	var (
		service    = auth.NewBasicAuthService(logger, userRepo, tokenRepo, helpers, os.Getenv("JWT_SECRET"))
		endpoints  = auth.MakeEndpoints(service)
		grpcServer = auth.NewGRPCServer(endpoints)
	)

	var g group.Group
	{
		grpcListener, err := net.Listen("tcp", *grpcAddr)
		if err != nil {
			logger.Log("transport", "gRPC", "during", "Listen", "err", err)
			os.Exit(1)
		}
		g.Add(func() error {
			logger.Log("transport", "gRPC", "addr", *grpcAddr)
			baseServer := grpc.NewServer(grpc.UnaryInterceptor(kitgrpc.Interceptor))
			pb.RegisterAuthServer(baseServer, grpcServer)

			return baseServer.Serve(grpcListener)
		}, func(error) {
			grpcListener.Close()
		})
	}
	{
		cancelInterrupt := make(chan struct{})
		g.Add(func() error {
			c := make(chan os.Signal, 1)
			signal.Notify(c, syscall.SIGINT, syscall.SIGTERM)
			select {
			case sig := <-c:
				return fmt.Errorf("received signal %s", sig)
			case <-cancelInterrupt:
				return nil
			}
		}, func(error) {
			close(cancelInterrupt)
		})
	}

	logger.Log("exit", g.Run())
}
