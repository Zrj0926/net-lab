#include "ip.h"

#include "arp.h"
#include "ethernet.h"
#include "icmp.h"
#include "net.h"

/**
 * @brief 处理一个收到的数据包
 *
 * @param buf 要处理的数据包
 * @param src_mac 源mac地址
 */
void ip_in(buf_t *buf, uint8_t *src_mac) {
    // TO-DO
    if(buf->len < sizeof(ip_hdr_t)) return;

    ip_hdr_t *hdr = (ip_hdr_t *) buf->data;
    if(hdr->version != IP_VERSION_4 || swap16(hdr->total_len16) > buf->len) return;

    uint16_t old_checksum = hdr->hdr_checksum16;
    hdr->hdr_checksum16 = 0;
    uint16_t now_checksum = checksum16((uint16_t *)buf->data, sizeof(ip_hdr_t));
    if(now_checksum == old_checksum) hdr->hdr_checksum16 = now_checksum;
    else return;

    if (memcmp(hdr->dst_ip, net_if_ip, NET_IP_LEN)) {
        return;
    }

    if (buf->len > swap16(hdr->total_len16)) {
        buf_remove_padding(buf, buf->len - swap16(hdr->total_len16));
    }

    buf_remove_header(buf, sizeof(ip_hdr_t));

    if (net_in(buf, hdr->protocol, hdr->src_ip)) {
        buf_add_header(buf, sizeof(ip_hdr_t));
        icmp_unreachable(buf, hdr->src_ip, ICMP_CODE_PROTOCOL_UNREACH);
    }

}
/**
 * @brief 处理一个要发送的ip分片
 *
 * @param buf 要发送的分片
 * @param ip 目标ip地址
 * @param protocol 上层协议
 * @param id 数据包id
 * @param offset 分片offset，必须被8整除
 * @param mf 分片mf标志，是否有下一个分片
 */
void ip_fragment_out(buf_t *buf, uint8_t *ip, net_protocol_t protocol, int id, uint16_t offset, int mf) {
    // TO-DO
    buf_add_header(buf, sizeof(ip_hdr_t));
    ip_hdr_t *hdr = (ip_hdr_t *)buf->data;

    hdr->version = IP_VERSION_4;
    hdr->hdr_len = sizeof(ip_hdr_t) / IP_HDR_LEN_PER_BYTE;
    hdr->tos = 0;
    hdr->total_len16 = swap16(buf->len);
    hdr->id16 = swap16(id);
    offset = (mf ? IP_MORE_FRAGMENT : 0) | offset;
    hdr->flags_fragment16 = swap16(offset);
    hdr->ttl = IP_DEFALUT_TTL;
    hdr->protocol = protocol;
    memcpy(hdr->src_ip, net_if_ip, NET_IP_LEN);
    memcpy(hdr->dst_ip, ip, NET_IP_LEN);

    hdr->hdr_checksum16 = 0;
    hdr->hdr_checksum16 = checksum16((uint16_t *)buf->data, sizeof(ip_hdr_t));

    arp_out(buf, ip);

}

/**
 * @brief 处理一个要发送的ip数据包
 *
 * @param buf 要处理的包
 * @param ip 目标ip地址
 * @param protocol 上层协议
 */
void ip_out(buf_t *buf, uint8_t *ip, net_protocol_t protocol) {
    // TO-DO
    size_t ip_len = ETHERNET_MAX_TRANSPORT_UNIT - sizeof(ip_hdr_t);
    static int id = 0;
    if(buf->len <= ip_len) {
        //不分片
        ip_fragment_out(buf, ip, protocol, id, 0, 0);
    }else{
        //分片
        buf_t ip_buf;
        uint16_t has_out = 0;
        uint16_t offset = 0;
        int mf;
        while(buf->len) {
            size_t fragment_len = (buf->len > ip_len) ? ip_len : buf->len;
            buf_init(&ip_buf, fragment_len);
            memcpy(ip_buf.data, buf->data, fragment_len);

            if(buf->len - fragment_len) mf = 1;
            else mf = 0;
            offset = has_out / IP_HDR_OFFSET_PER_BYTE;

            ip_fragment_out(&ip_buf, ip, protocol, id, offset, mf);

            has_out += fragment_len;
            buf->data += fragment_len;
            buf->len -= fragment_len;
        }
    }
    id++;
}

/**
 * @brief 初始化ip协议
 *
 */
void ip_init() {
    net_add_protocol(NET_PROTOCOL_IP, ip_in);
}