# 使用 Go 1.21 官方镜像作为构建环境
FROM golang:1.21 AS builder

# 禁用 CGO
ENV CGO_ENABLED=0

# 设置工作目录
WORKDIR /app

# 复制 go.mod 和 go.sum 并下载依赖
COPY go.mod go.sum ./
RUN go mod download

# 复制源代码并构建应用
COPY . .
RUN go build -ldflags "-s -w" -o /app/randomproxy .


FROM ubuntu

# 设置工作目录
WORKDIR /app

# 从构建阶段复制编译好的应用和资源
COPY --from=builder /app/randomproxy /app/randomproxy

RUN apt-get update && \
    apt-get install -yq tzdata && \
    ln -fs /usr/share/zoneinfo/Asia/Shanghai /etc/localtime && \
    dpkg-reconfigure -f noninteractive tzdata && \
    apt-get install -yq curl && \
    apt-get install -yq ca-certificates


# 赋予应用执行权限
RUN chmod +x /app/randomproxy

# 暴露端口
EXPOSE 31280

# 设置启动命令
CMD ["/app/randomproxy"]
