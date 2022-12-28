#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <string>
#include <unistd.h>

#include <enclave_u.h>
#include <getopt.h>
#include "ulog_utils.h"

// Need to create enclave and do ecall.
#include "sgx_urts.h"

#include <netdb.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "fifo_def.h"
#include "datatypes.h"

#include "la_task.h"
#include "la_server.h"
#include "auto_version.h"
#include <thread>

#define __STDC_FORMAT_MACROS
#define ENCLAVE_PATH "libenclave-ehsm-dkeycache.signed.so"
#include <inttypes.h>

sgx_enclave_id_t g_enclave_id;

void ocall_print_string(uint32_t log_level, const char *str, const char *filename, uint32_t line)
{
    switch (log_level)
    {
    case LOG_INFO:
    case LOG_DEBUG:
    case LOG_ERROR:
    case LOG_WARN:
        log_c(log_level, str, filename, line);
        break;
    default:
        log_c(LOG_ERROR, "log system error in ocall print.\n", filename, line);
        break;
    }
}

int ocall_close(int fd)
{
    return close(fd);
}

void ocall_get_current_time(uint64_t *p_current_time)
{
    time_t rawtime;
    time(&rawtime);

    if (!p_current_time)
        return;
    *p_current_time = (uint64_t)rawtime;
}

/* ocalls to use socket APIs , call socket syscalls */

int ocall_socket(int domain, int type, int protocol)
{
    return socket(domain, type, protocol);
}

int ocall_connect(int sockfd, const struct sockaddr *servaddr, socklen_t addrlen)
{
    int32_t retry_count = 10;
    do
    {
        int ret = connect(sockfd, servaddr, addrlen);
        if (ret >= 0)
            return ret;

        log_i("Failed to Connect dkeyserver, sleep 0.5s and try again...\n");
        usleep(500000); // 0.5s
    } while (retry_count-- > 0);

    log_e("Failed to connect dkeyserver.\n");
    return -1;
}

int ocall_set_dkeycache_done()
{
    return (system("touch /tmp/dkeycache_isready.status"));
}

LaTask *g_la_task = NULL;
LaServer *g_la_server = NULL;

std::string deploy_ip_addr;
uint16_t deploy_port = 0;
static const char *_sopts = "i:p:";
static const struct option _lopts[] = {{"ip", required_argument, NULL, 'i'},
                                       {"port", required_argument, NULL, 'p'},
                                       {0, 0, 0, 0}};

void signal_handler(int sig)
{
    switch (sig)
    {
    case SIGINT:
    case SIGTERM:
    {
        if (g_la_server)
            g_la_server->shutDown();
    }
    break;
    default:
        break;
    }

    exit(1);
}

void cleanup()
{
    if (g_la_task != NULL)
        delete g_la_task;
    if (g_la_server != NULL)
        delete g_la_server;
}

static void show_usage_and_exit(int code)
{
    log_i("\nusage: ehsm-dkeycache -i 127.0.0.1 -p 8888\n\n");
    exit(code);
}
static void parse_args(int argc, char *argv[])
{
    int opt;
    int oidx = 0;
    while ((opt = getopt_long(argc, argv, _sopts, _lopts, &oidx)) != -1)
    {
        switch (opt)
        {
        case 'i':
            deploy_ip_addr = strdup(optarg);
            break;
        case 'p':
            try
            {
                deploy_port = std::stoi(strdup(optarg));
            }
            catch (...)
            {
                log_e("[-p %s] port must be a number.", optarg);
            }
            break;
        default:
            log_e("unrecognized option (%c):\n", opt);
            show_usage_and_exit(EXIT_FAILURE);
        }
    }
    if (deploy_ip_addr.empty() || deploy_port == 0)
    {
        log_e("error: missing required argument(s)\n");
        show_usage_and_exit(EXIT_FAILURE);
    }
}

typedef struct CPUPACKED
{
    char name[20];       // 定义一个char类型的数组名name有20个元素
    unsigned int user;   // 定义一个无符号的int类型的user
    unsigned int nice;   // 定义一个无符号的int类型的nice
    unsigned int system; // 定义一个无符号的int类型的system
    unsigned int idle;   // 定义一个无符号的int类型的idle
    unsigned int lowait;
    unsigned int irq;
    unsigned int softirq;
} CPU_OCCUPY;

double getCpuUse(CPU_OCCUPY *o, CPU_OCCUPY *n)
{
    unsigned long od, nd;
    od = (unsigned long)(o->user + o->nice + o->system + o->idle + o->lowait + o->irq + o->softirq); // 第一次(用户+优先级+系统+空闲)的时间再赋给od
    nd = (unsigned long)(n->user + n->nice + n->system + n->idle + n->lowait + n->irq + n->softirq); // 第二次(用户+优先级+系统+空闲)的时间再赋给od
    double sum = nd - od;
    double idle = n->idle - o->idle;
    return (sum - idle) / sum;
}

void printCpuUse(std::string prefix, bool onWhile)
{
    CPU_OCCUPY old_cpu_occupy;
    do
    {
        FILE *fd;       // 定义打开文件的指针
        char buff[256]; // 定义个数组，用来存放从文件中读取CPU的信息
        CPU_OCCUPY cpu_occupy;
        std::string cpu_use = "";

        fd = fopen("/proc/stat", "r");

        if (fd != NULL)
        {
            // 读取第一行的信息，cpu整体信息
            fgets(buff, sizeof(buff), fd);
            if (strstr(buff, "cpu") != NULL) // 返回与"cpu"在buff中的地址，如果没有，返回空指针
            {
                // 从字符串格式化输出
                sscanf(buff, "%s %u %u %u %u %u %u %u", cpu_occupy.name, &cpu_occupy.user, &cpu_occupy.nice, &cpu_occupy.system, &cpu_occupy.idle, &cpu_occupy.lowait, &cpu_occupy.irq, &cpu_occupy.softirq);
                // cpu的占用率 = （当前时刻的任务占用cpu总时间-前一时刻的任务占用cpu总时间）/ （当前时刻 - 前一时刻的总时间）
                cpu_use = std::to_string(getCpuUse(&old_cpu_occupy, &cpu_occupy) * 100) + "%";
                old_cpu_occupy = cpu_occupy;
            }
        }
        log_w("========> %s getCpuUse = %s", prefix.c_str(), cpu_use.c_str());
        // log_w("========> getCpuUse = %s", cpu_use.c_str());
        if (onWhile)
        {
            sleep(1); // 延时1s；
        }
    } while (onWhile);
}

int main(int argc, char *argv[])
{
    // mkdir RUNTIME_FOLDER
    if (access(RUNTIME_FOLDER, F_OK) != 0)
    {
        printf("Initializing runtime folder [path: %s].\n", RUNTIME_FOLDER);
        if (mkdir(RUNTIME_FOLDER, 0755) != 0)
        {
            printf("Create runtime folder failed!\n");
            return -1;
        }
    }
    if (initLogger("dkeycache.log") < 0)
        return -1;
    log_i("Service name:\t\tDomainKey Caching Service %s", EHSM_VERSION);
    log_i("Service built:\t\t%s", EHSM_DATE);
    log_i("Service git_sha:\t\t%s", EHSM_GIT_SHA);
    printCpuUse("end init logger", false);

    // process argv
    parse_args(argc, argv);
    printCpuUse("end parse args", false);

    log_i("Runtime folder:\t\t%s", RUNTIME_FOLDER);
    log_i("DomainKey Server IP:\t\t%s", deploy_ip_addr.c_str());
    log_i("DomainKey Server port:\t%d", deploy_port);

    int ret = 0;

    ret = sgx_create_enclave(_T(ENCLAVE_PATH),
                             SGX_DEBUG_FLAG,
                             NULL,
                             NULL,
                             &g_enclave_id, NULL);
    if (SGX_SUCCESS != ret)
    {
        log_e("failed(%d) to create enclave.\n", ret);
        return -1;
    }
    printCpuUse("end create enclave", false);

    // Connect to the dkeyserver and retrieve the domain key via the remote secure channel
    log_i("Host: launch TLS client to initiate TLS connection\n");
    ret = enclave_launch_tls_client(g_enclave_id, &ret, deploy_ip_addr.c_str(), deploy_port);
    if (ret != 0)
    {
        log_e("failed to initialize the dkeycache service.\n");
        sgx_destroy_enclave(g_enclave_id);
    }
    printCpuUse("end Connect dkeyserver", false);

    // create server instance, it would listen on sockets and proceeds client's requests
    g_la_task = new (std::nothrow) LaTask;
    g_la_server = new (std::nothrow) LaServer(g_la_task);

    if (!g_la_task || !g_la_server)
        return -1;
    printCpuUse("end new task and server", false);

    atexit(cleanup);
    printCpuUse("end atexit", false);

    // register signal handler so to respond to user interception
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    printCpuUse("end signal", false);

    g_la_task->start();
    printCpuUse("end task start", false);

    if (g_la_server->init() != 0)
    {
        log_e("fail to init dkeycache service!\n");
    }
    else
    {
        log_i("dkeycache service is ON...\n");
        std::thread(printCpuUse, "end server init", true).detach();
        log_i("Press Ctrl+C to exit...\n");
        g_la_server->doWork();
    }

    logger_shutDown();

    sgx_destroy_enclave(g_enclave_id);

    return 0;
}
