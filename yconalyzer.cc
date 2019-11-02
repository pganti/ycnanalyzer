/*
 * yconalyzer: A program to analyze TCP traffic on a server or client port.
 *
Software Copyright License Agreement (BSD License)

Copyright (c) 2010, Yahoo! Inc.
All rights reserved.

Redistribution and use of this software in source and binary forms, 
with or without modification, are permitted provided that the following 
conditions are met:

* Redistributions of source code must retain the above
  copyright notice, this list of conditions and the
  following disclaimer.

* Redistributions in binary form must reproduce the above
  copyright notice, this list of conditions and the
  following disclaimer in the documentation and/or other
  materials provided with the distribution.

* Neither the name of Yahoo! Inc. nor the names of its
  contributors may be used to endorse or promote products
  derived from this software without specific prior
  written permission of Yahoo! Inc.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS 
IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED 
TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A 
PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT 
OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, 
SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT 
LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, 
DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY 
THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT 
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE 
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "yconalyzer.h"

#define RTT_EST_ENABLED "RTT Estimation enabled.\n"
#define MAX_SYNACKS 4
#define DEFAULT_MAX_RTT	1100	// in msecs. see max_rtt

// tcphdr and tcp_seq taken from netinet/tcp.h in BSD
typedef u_int32_t tcp_seq;
struct tcphdr {
	u_short	th_sport;		/* source port */
	u_short	th_dport;		/* destination port */
	tcp_seq	th_seq;			/* sequence number */
	tcp_seq	th_ack;			/* acknowledgement number */
#if BYTE_ORDER == LITTLE_ENDIAN
	u_int	th_x2:4,		/* (unused) */
		th_off:4;		/* data offset */
#endif
#if BYTE_ORDER == BIG_ENDIAN
	u_int	th_off:4,		/* data offset */
		th_x2:4;		/* (unused) */
#endif
	u_char	th_flags;
#define	TH_FIN	0x01
#define	TH_SYN	0x02
#define	TH_RST	0x04
#define	TH_PUSH	0x08
#define	TH_ACK	0x10
#define	TH_URG	0x20
#define	TH_ECE	0x40
#define	TH_CWR	0x80
#define	TH_FLAGS	(TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)

	u_short	th_win;			/* window */
	u_short	th_sum;			/* checksum */
	u_short	th_urp;			/* urgent pointer */
};

#include <string>

#if __GNUC__ > 2
#include <map>
using namespace _GLIBCXX_STD;
// Linux gcc-3 is not too happy with the format strings we use in BSD.
#define KEY_FMT_STRING "%#8x%#4x"

#else	/* We are using gnu-c <= 2 */

#include <hash_map.h>
#define KEY_FMT_STRING "%8ux%4hx"

#endif

static int debug = 0;
static u_short port = 0;
static int nbuckets;
static int bucket_size;
static int lo_bucket = 0;
static unsigned long min_srvr_rspsize = 0;
static unsigned long min_clnt_reqsize = 0;
static unsigned long max_srvr_rspsize = 0;
static unsigned long max_clnt_reqsize = 0;
static int find_rtt = 0;
static bool fromfile = false;
static bool raw_output = false;
static int gottime = 0;
static pcap_dumper_t *dumper = NULL;
static int output_version = 0;
static int min_conntime = 0;
static unsigned long min_conn_attempts = 0;
static int done = 0;
static enum {
	REP_DURATION = 1,	// sort by duration
	REP_THRUPUT,	// sort by throughput
	REP_CLBYTES,	// sort by bytes sent by client.
	REP_SRBYTES,	// sort by bytes sent by the server.
} report_type;

// Maximum RTT (in msecs). When we try to estimate RTT using the FIN bits in
// the packets, we can have errors in RTT estimation. In order to minimize
// those errors, if we end up with an RTT number of more than this value, we
// should abandon estimating RTT for that connection. It could be that the
// client was busy, or somehow failed to send a FIN in time, etc.
static int max_rtt = DEFAULT_MAX_RTT;

#define NBUCKETS 20
#define BUCKET_SIZE 20	// msecs

struct portdet {
	struct in_addr ipsrc;
	struct in_addr ipdst;
	int port;
};

typedef enum {
	CLOSED = 0,
	CONNECTING = 1,
	CONNECTED = 2,
	CLOSING = 3,
} state_t ;

struct conndet {
	struct timeval st_time;		// Conn start time. we see first SYN
	struct timeval cl_time;		// Time it moved into CLOSING state
	int st_rtt;			// Sample round trip time.
	unsigned long st_seq_client;	// Init seqno of client
	unsigned long st_seq_server;	// Init seq number of server
	unsigned long st_seq_client2;	// some abusive clients send a second SYN
	struct timeval st_time2;	// time on second SYN
	// Sometimes, we see the SYN|ACK before SYN because of packet
	// reordering in pcap. Or, the SYN|ACK could be dropped. In either
	// case, we would create a conndet object, but not be able to
	// initialize the server seq number. As a result, the server data
	// will end up being very large.
	state_t state;			// current state of the connection
	unsigned long nsyns;		// Number of syns to get established.
	struct in_addr synsender;	// sender of the SYN
	struct in_addr finsender;	// sender of the first FIN.
	int port;			// src port.
	int synack_txmts;		// number of transmissions of synack
	unsigned int thruput;		// throughput
	int bucket;			// when we determine its bucket.
};


struct bucket {
	long long nconns;	// Number of connections in bucket.
	long long clsize;	// Total number of bytes sent by all clients.
	long long srsize;	// Total number of bytes sent by all servers
	int rtt;		// Total estimated RTT of all connections
	long long msecs;	// Total duration of all connections.
	long long thruput;	// Throughput of this connection.
};

static unsigned long nsyns;	// total number of syns seen.
static unsigned long ndupsyns;	// Number of duplicate syns seen.
static unsigned long nsyns2estab;   // number of syns it took to estab the conns
static unsigned long nsyns2drop;    // number of syns taken up by dropped conns
static unsigned long ndroppedconns; // number conns never completed.
static unsigned long ninprogress;   // number of conns in progress at the end
static unsigned long ndiscarded;    // a guess on number of conns discarded
				    // due to max retransmission of syn|ack
				    // pkt. Useful in the server side.
static unsigned long nresets;	    // number of conns terminated by reset.
static unsigned long nclosing;	    // Number of conns in CLOSING state.
//static unsigned long maxnsyns;	    // max number of syns to estab a conn.
static long long nconns;
static long long clsize;
static long long srsize;
static long long conntime;
static long long total_rtt;
static struct bucket *buckets;
static int lo_val = -1;
static int hi_val = -1;

#if __GNUC__ > 2
typedef map<int, int> addrhash;
typedef map<std::string, struct conndet *> connhash;
typedef map<unsigned long, unsigned long> nsynshash;
#else // gnu <= 2
struct hashtest
{
    size_t operator()( const std::string& x ) const
    {
        return hash< const char* >()( x.c_str());
    }
};

typedef hash_map<int, int> addrhash;
typedef hash_map<std::string, struct conndet *, hashtest> connhash;
typedef hash_map<unsigned long, unsigned long> nsynshash;
#endif

//long long st_time;
static struct timeval trace_st_time;	// Dump start time
static struct timeval trace_end_time;    // Dump end time
static struct timeval filter_st_time;
static const char * filter_st_time_str = NULL;	// Ignore packets before this time (string).

// A hash table of connections that we know about. 
static connhash tab;
// A hash of local addresses, all in network byte order.
static addrhash addrs;
// Port numbers with connection duration higher than lo_val and lower
// than hi_val.
static vector <struct portdet> portsvec;
static nsynshash synhash;

#define LOG_INFO(x_fmt, x_args...) fprintf(stderr, "%s:%d:" x_fmt "\n", __FILE__, __LINE__ , ##x_args)
#define LOG_WARNING(x_fmt, x_args...) fprintf(stderr, "%s:%d:" x_fmt "\n", __FILE__, __LINE__ , ##x_args)
#define LOG_ERROR(x_fmt, x_args...) fprintf(stderr, "%s:%d:" x_fmt "\n", __FILE__, __LINE__ , ##x_args)
#define LOG_DEBUG(x_fmt, x_args...) if (debug) fprintf(stdout, "%s:%d:" x_fmt "\n", __FILE__, __LINE__ , ##x_args)
#define LOG_TRACE(x_fmt, x_args...) if (debug) fprintf(stdout, x_fmt, ##x_args)
#define LOG_DDEBUG(x_fmt, x_args...) if (debug > 1) fprintf(stdout, "%s:%d:" x_fmt "\n", __FILE__, __LINE__ , ##x_args)

// Output versions, so that we don't break scripts that depend on a certain output format.
#define OUTPUT_VERSION_1 1
// Experimental stuff. When finalized, bump output version to next number and retain
// backward compatibility with cmd line options or compile flags, may be.
#define OUTPUT_EXPERIMENTAL 999

static pcap_t	*pc = NULL;
static int datalink = -1;

// Forward declaration
static void end_process();
static void print_duration();
static void print_thruput();
static void print_bytes();

static void
usage(char *cmd)
{
	fprintf(stderr, "Usage: %s -p port [-d] [-R] [-r from_file] [-w to_file] [-i ifname] [-n nbuckets] [-s bucket size] [-X max-srvr-rsp-size] [ -x max-clnt-req-size] [-T]  [-D msecs] [-P|-C|-S] [-c num_attempts] [-I timespec] [filter]\n", cmd);
	fprintf(stderr, "-d: Debug on (default off)\n");
	fprintf(stderr, "-c: Print connections that took >= num_attempts to establish\n");
	fprintf(stderr, "-R: Raw format output. Useful for scripts\n");
	fprintf(stderr, "-r: Data is read from file instead of live interface\n");
	fprintf(stderr, "-w: Data is written to a file.\n");
	fprintf(stderr, "-i: Interface name (default is ethernet interface)\n");
	fprintf(stderr, "-n: Number of buckets for getting the distribution. Default 20\n");
	fprintf(stderr, "-s: Bucket size (connection life time). Default 20ms\n");
	fprintf(stderr, "-t: Run time in seconds (default 60)\n");
	fprintf(stderr, "-X: Consider only those connections where the server sends data less than this number. 0 considers all conns (default)\n");
	fprintf(stderr, "-x: Consider only those connections where the client sends data less than this number. 0 considers all conns (default)\n");
	fprintf(stderr, "-Y: Consider only those connections where the server sends data more than this number. 0 considers all conns (default)\n");
	fprintf(stderr, "-y: Consider only those connections where the client sends data more than this number. 0 considers all conns (default)\n");
	fprintf(stderr, "  Only one of -x or -X can be specified\n");
	fprintf(stderr, "-T: Attempt to estimate round trip time\n");
	fprintf(stderr, "  Estimates may be wrong if the command is run on the server side. See man page.\n");
	fprintf(stderr, "-D: Print connection filters for the bucket starting with this value\n");
	fprintf(stderr, "  Useful when yconalyzer reads from file. You can then filter by port to look at individual connection trace\n");
	fprintf(stderr, "-p: port number you want to monitor. Must be specified\n");
	fprintf(stderr, "-I: Consider pkts newer than this time. Specify in HH:MM:SS or YYYY-MM-DD.HH:MM:SS format\n");
	fprintf(stderr, "-P for sorting the output by throughput\n");
	fprintf(stderr, "-C for sorting the output by number of bytes sent by client\n");
	fprintf(stderr, "-S for sorting the output by number of bytes sent by server\n");
	fprintf(stderr, "filter: Optional, specified as in tcpdump(1)\n");
	fprintf(stderr, "Connections are placed in one of the buckets depending on duration\n");
	fprintf(stderr,"You must be super-user to run this program\n");
	fprintf(stderr, "Type 'man yconalyzer' for more information\n");
	exit(1);
}

static bool
str_2_tm(struct tm *tm)
{
	char *rv;
	const char *dash = strchr(filter_st_time_str, '-');
	const char *fmt = "%H:%M:%S";
	if (dash != NULL) {
		fmt = "%Y-%m-%d.%H:%M:%S";
	}
	rv = strptime(filter_st_time_str, fmt, tm);
	if (rv == NULL) {
		fprintf(stderr, "Illegal time string\n");
		return (false);
	}
	if (*rv != 0) {
		fprintf(stderr, "Illegal time string: %s\n", rv);
		return (false);
	}
	return true;
}

static void
set_start_time(const struct timeval *tv)
{
	struct tm tm1, tm2, *tmp;
	time_t timet = tv->tv_sec;
	tmp = localtime(&timet);
	tm1 = *tmp;
	memset(&tm2, 0, sizeof (tm2));
	(void) str_2_tm(&tm2);
	if (tm2.tm_mday) {
		tm1.tm_mday = tm2.tm_mday;
		tm1.tm_mon = tm2.tm_mon;
		tm1.tm_year = tm2.tm_year;
	}
	tm1.tm_sec = tm2.tm_sec;
	tm1.tm_min = tm2.tm_min;
	tm1.tm_hour = tm2.tm_hour;
	filter_st_time.tv_sec = mktime(&tm1);
	filter_st_time.tv_usec = 0;
}

static pcap_t	*
open_pcap(char *fname, char *device, int snaplen, int promisc, int to_ms)
{
	char	errbuf[PCAP_ERRBUF_SIZE];
	pcap_t	*rc;

	errbuf[0] = 0;

	if (fname[0] == 0) {
		rc = pcap_open_live(device, snaplen, promisc, to_ms, errbuf);
	} else {
		rc = pcap_open_offline(fname, errbuf);
	}
	if (rc == NULL) {
		LOG_ERROR("%s", errbuf);
	} else if (errbuf[0] != 0) {
		LOG_WARNING("%s", errbuf);
	}
	return (rc);
}

static char *
find_dev()
{
	pcap_if_t *alldevs;
	int	rv;
	char	errbuf[PCAP_ERRBUF_SIZE];
	char	*rc = NULL;

	// Look up all devices and get a hash of the addresses.
	errbuf[0] = 0;
	rv = pcap_findalldevs(&alldevs, errbuf);
	// Usually returns 0 all the time
	if (rv != 0)  {
		printf("pcap_findalldevs:%d:%s\n", rv, errbuf);
		return (rc);
	}
	for (;alldevs != NULL; alldevs = alldevs->next) {
		//if (alldevs->flags & PCAP_IF_LOOPBACK) {
			//continue;
		//}
		LOG_DDEBUG("Examining interface: %s\n", alldevs->name);
		pcap_addr_t *paddr;
		for (paddr = alldevs->addresses; paddr != NULL && paddr->addr != NULL;
				paddr = paddr->next) {
			if (paddr->addr->sa_family == AF_INET) {
				int addr = ((struct sockaddr_in *)(paddr->addr))->sin_addr.s_addr;
				LOG_DDEBUG("Found Inet address 0x%x\n", addr);
				// 'addr' is in network byte order.
				addrs[addr] = 1;

			}
		}
		//rc = alldevs->name;
	}
	pcap_freealldevs(alldevs);

	// The real lookup to bind to a default device.
	rc = pcap_lookupdev(errbuf);
	if (rc == NULL) {
		LOG_ERROR("pcap_lookupdev:%s", errbuf);
		return (NULL);
	}
	return (rc);
}

static int
get_ip_hdr(const u_char *pkt, u_char **ip)
{
	struct ether_header *eh;
	uint16_t    etype;
	unsigned long pf;

	if (datalink == DLT_EN10MB) {
		eh = (struct ether_header *)pkt;
		etype = ntohs(eh->ether_type);
		if (etype == ETHERTYPE_IP) {
			*ip = (u_char *)(pkt + sizeof (struct ether_header));
			return (0);
		}
	} else if (datalink == DLT_NULL) {
		pf = *(unsigned long *)(pkt);
		if (pf == PF_INET) {
			*ip = (u_char *)(pkt + sizeof (unsigned long));
			return (0);
		}
	}
	return (-1);
}

static u_char
get_proto(const u_char *pkt, u_char **tcp)
{
	struct	ip *ip = (struct ip *)pkt;
	int hlen = ip->ip_hl * 4;
	u_char proto = ip->ip_p;

	*tcp = (u_char *)(pkt + hlen);
	return (proto);
}


static void
process_syn(const struct timeval *tv, struct tcphdr *tcph,
		struct in_addr *ipsrc, struct in_addr *ipdst)
{
	u_short sport = ntohs(tcph->th_sport);
	u_short dport = ntohs(tcph->th_dport);
	//u_short hash_port = (sport != port) ? sport : dport;
	u_short hash_port  = ntohs(tcph->th_sport);
	char key[64];

	snprintf(key, sizeof (key), KEY_FMT_STRING, ipsrc->s_addr, hash_port);

	connhash::iterator it = tab.find(key);
	struct conndet * cd;

	if (it != tab.end()) {
		cd = it->second;
		// If this is a SYN coming in, then it could well be that we
		// sent the SYN|ACK but that got dropped. We should not be
		// accounting that against the number of SYNs taken to
		// establish a connection.
		// Also, if this is an outgoing SYN, the fact that
		// the state is still CONNECTING means we are
		// retransmitting the SYN, and therefore we count it
		// correctly against the number of SYNs taken up to get a
		// connection through.
		if ((cd->state == CONNECTING) ||
				((cd->state == CONNECTED) && (cd->st_seq_client == ntohl(tcph->th_seq)))) {
			// This is a retransmitted SYN for the connection,
			// whether we are running on the client or on the
			// server.
			ndupsyns++;
			cd->nsyns++;
			nsyns++;
			cd->st_time = *tv;
			cd->st_seq_client = ntohl(tcph->th_seq);
			cd->state = CONNECTING;
			cd->st_rtt = 0;
			cd->synack_txmts = 0;
			cd->port = hash_port;
		} else {
		// A second SYN came in while we are connected. It could be
		// that the client dropped the SYN|ACK, and is sending a
		// separate SYN -- a retry.
		// Or, it could be that this is a buggy/abusive client that is
		// trying to sneak in a SYN in the middle of the connection.
		// Only our SYN|ACK can tell whether or not we changed the
		// face of this connection. Retain the old state, and remember
		// that this came in.
			cd->st_seq_client2 = ntohl(tcph->th_seq);
			cd->st_time2 = *tv;
		}
	} else {
		cd = new conndet;
		tab[key] = cd;
		cd->nsyns = 1;
		cd->synsender.s_addr = ipsrc->s_addr;
		nsyns++;
		cd->bucket = -1;
		cd->state = CONNECTING;
		cd->st_time = *tv;
		cd->st_seq_client = ntohl(tcph->th_seq);
		cd->st_rtt = 0;
		cd->synack_txmts = 0;
		cd->port = hash_port;
		cd->st_time2.tv_sec = 0;
		cd->st_time2.tv_usec = 0;
	}

	if (debug) {
		// Calling inet_ntoa() twice in the same print statements will
		// muddle the ip addresses.
		LOG_TRACE("%s:%hu > ", inet_ntoa(*ipsrc), sport);
		LOG_TRACE("%s:%hu S SEQ:%lu\n", inet_ntoa(*ipdst), dport, cd->st_seq_client);
	}
}


static int
add_stats(int msecs, unsigned int clbytes, unsigned int srbytes,
		struct conndet *cd)
{
	int bucket;

	nconns++;
	clsize += clbytes;
	srsize += srbytes;
	conntime += msecs;
	total_rtt += cd->st_rtt;

	if (report_type == REP_THRUPUT) {
		unsigned int nb = clbytes > srbytes ? clbytes : srbytes;
		if (msecs == 0) {
			msecs = 1;
		}
		cd->thruput = nb / msecs;   // KB/sec

		bucket = (cd->thruput / bucket_size) - lo_bucket;
	} else if (report_type == REP_CLBYTES) {
		bucket = (clbytes / bucket_size / 1024) - lo_bucket;	// bucket size is in KB
	} else if (report_type == REP_SRBYTES) {
		bucket = (srbytes / bucket_size / 1024) - lo_bucket;
	} else {    // default is duration
		bucket = (msecs / bucket_size) - lo_bucket;
	}

	if (bucket > nbuckets) {
		bucket = nbuckets;
	} else if (bucket < 0) {
		LOG_ERROR("Bad bucket value:%d\n", bucket);
		abort();
	}

	buckets[bucket].nconns++;
	buckets[bucket].clsize += clbytes;
	buckets[bucket].srsize += srbytes;
	buckets[bucket].rtt += cd->st_rtt;
	buckets[bucket].msecs += msecs;
	buckets[bucket].thruput += ((srbytes+clbytes)/(msecs+1));
	return (bucket);
}

static int
tvdiff_msecs(const struct timeval *tv1, const struct timeval *tv2)
{
	long u = tv2->tv_usec - tv1->tv_usec;
	long s = tv2->tv_sec - tv1->tv_sec;
	if (u < 0) {
		u += 1000000;
		s -= 1;
	}
	if (s < 0 || u < 0) {
		// OSX-SnowLeopard has problems with a %ld for timeval
		LOG_DEBUG("Bad value of time:%ld/%ld, %ld/%ld\n",
				(long)(tv1->tv_sec), (long)(tv1->tv_usec),
				(long)(tv2->tv_sec), (long)(tv2->tv_usec));
		return (0);
	}
	return (s * 1000 + u / 1000);
}

// If max_srvr_rspsize has been set, then we need to
// take in only those conns where the server
// sends less data than the size indicated.
// Similarly, if the max_clnt_reqsize is set, then
// we need to account for only those conns where the
// client sends data less than value set in
// max_clnt_reqsize.
static bool
include_connection(unsigned long clbytes, unsigned long srbytes)
{
	if (max_srvr_rspsize != 0 && srbytes > max_srvr_rspsize) {
		return (false);
	}
	if (min_srvr_rspsize != 0 && srbytes < min_srvr_rspsize) {
		return (false);
	}
	if (max_clnt_reqsize != 0 && clbytes > max_clnt_reqsize) {
		return (false);
	}
	if (min_clnt_reqsize != 0 && clbytes < min_clnt_reqsize) {
		return (false);
	}
	return (true);
}

static void
process_end_conn(const struct timeval *tv, struct tcphdr *tcph,
		struct in_addr *ipsrc, struct in_addr *ipdst, bool reset,
		int datalen)
{
	u_short sport = ntohs(tcph->th_sport);
	u_short dport = ntohs(tcph->th_dport);
	u_short hash_port = (sport != port) ? sport : dport;
	char key[64];
	//long long trace_end_time;
	//unsigned long end_seq;
	unsigned long cl_end_seq, sr_end_seq;

	if (hash_port == sport) {
		// client is intiating the FIN
		snprintf(key, sizeof (key), KEY_FMT_STRING,
				ipsrc->s_addr, hash_port);
		cl_end_seq = ntohl(tcph->th_seq) + datalen;
		sr_end_seq = ntohl(tcph->th_ack);
	} else {
		//Server is initiating the FIN
		snprintf(key, sizeof (key), KEY_FMT_STRING,
				ipdst->s_addr, hash_port);
		cl_end_seq = ntohl(tcph->th_ack);
		sr_end_seq = ntohl(tcph->th_seq) + datalen;
	}

	connhash::iterator it = tab.find(key);

	if (it != tab.end()) {
		struct conndet * cd = it->second;
		if (cd->state == CLOSING) {
			// This is the second FIN or reset of the connection
			// If it is a retransmt of the FIN, just set the
			// time again. Never trust a RESET, however.
			if (!reset) {
				if (cd->finsender.s_addr == ipsrc->s_addr) {
					cd->cl_time = *tv;
					return;
				}
				// It is the other side sending the FIN.
				// Taking the time difference between now
				// and when we sent the FIN can give us a
				// rough idea of the rtt, in most cases.
				// Discard the rtt if it is more than
				// max_rtt, because it may be bogus -- may
				// be the client was too busy to respond to
				// our FIN..
				// Also, if our current estimate of RTT (from
				// the SYN exchange) is more than zero, then it
				// is likely that this trace was captured in
				// the client.
				int rtt = tvdiff_msecs(&(cd->cl_time), tv);
				if ((rtt < max_rtt) && (cd->st_rtt == 0) && (rtt > cd->st_rtt) && (cd->bucket >= 0)) {
					int bucket = cd->bucket;
					buckets[bucket].rtt += rtt;
					total_rtt += rtt;
				}
			}
			delete cd;
			tab.erase(key);
			return;
		}
		if ((cd->state == CONNECTED) && !reset) {
			unsigned long clbytes, srbytes;
			clbytes = cl_end_seq - cd->st_seq_client;
			srbytes = sr_end_seq - cd->st_seq_server;
			int msecs = tvdiff_msecs(&(cd->st_time), tv);
			cd->cl_time = *tv;
			cd->state = CLOSING;
			cd->finsender.s_addr = ipsrc->s_addr;
			if (include_connection(clbytes, srbytes)) {
				// This is the type of req we want to count
				if (debug) {
					LOG_TRACE("%s:%hu > ",
							inet_ntoa(*ipsrc),
							sport);
					LOG_TRACE("%s:%hu F SEQ:%lu(%lu),ACK:%lu(%lu),MSECS:%d\n",
							inet_ntoa(*ipdst),
							dport,
							sport == hash_port ? cl_end_seq : sr_end_seq,
							sport == hash_port ? clbytes : srbytes,
							sport == hash_port ? sr_end_seq : cl_end_seq,
							sport == hash_port ? srbytes : clbytes,
							msecs);
				}
				cd->bucket = add_stats(msecs, clbytes, srbytes, cd);
				int cmpval;
				if (report_type == REP_THRUPUT) {
					cmpval = cd->thruput;
				} else if (report_type == REP_CLBYTES) {
					cmpval = clbytes/1024;
				} else if (report_type == REP_SRBYTES) {
					cmpval = srbytes/1024;
				} else {    // default is duration
					cmpval = msecs;
				}
				if ((lo_val != -1) && (cmpval >= lo_val) && ((hi_val == -1) || (cmpval < hi_val))) {
					// If we knew whether the machine
					// that captured these packets is
					// the initiator or the server, then
					// we can the right IP address to
					// display. Failing that, the best
					// way is to display both IP
					// address. It would have been great
					// if libpcap provided a 3-way flag
					// indicating in/out/neither -- oh
					// well.
					struct portdet pd;
					pd.ipsrc = *ipsrc;
					pd.ipdst = *ipdst;
					pd.port = hash_port;
					portsvec.push_back(pd);
				}
				if (min_conn_attempts && 
						cd->nsyns >= min_conn_attempts) {

					printf("NSYNS=%lu:host %s and port %d\n",
						cd->nsyns,
						inet_ntoa(cd->synsender), cd->port);
				}
				nsyns2estab += cd->nsyns;
				nsynshash::iterator it;
				it = synhash.find(cd->nsyns);
				if (it == synhash.end()) {
					synhash[cd->nsyns] = 1;
				} else {
					it->second++;
				}

#if 0
				if (cd->nsyns > maxnsyns) {
					maxnsyns = cd->nsyns;
				}
#endif
			}
		} else if (reset) {
			LOG_DDEBUG("Conn Reset:%s\n", key);
			nresets++;
			delete cd;
			tab.erase(key);
			return;
		}
	}
}
static void
process_synack(const struct timeval *tv, struct tcphdr *tcph,
		struct in_addr *ipsrc, struct in_addr *ipdst)
{
	u_short sport = ntohs(tcph->th_sport);
	u_short dport = ntohs(tcph->th_dport);
	u_short hash_port = (sport != port) ? sport : dport;
	char key[64];

	if (hash_port == sport) {
		snprintf(key, sizeof (key), KEY_FMT_STRING,
				ipsrc->s_addr, hash_port);
	} else {
		snprintf(key, sizeof (key), KEY_FMT_STRING,
				ipdst->s_addr, hash_port);
	}

	connhash::iterator it = tab.find(key);
	unsigned long seq = ntohl(tcph->th_seq);
	unsigned long ack = ntohl(tcph->th_ack);

	if (it != tab.end()) {
		struct conndet * cd = it->second;
		if (cd->state == CONNECTED) {
			// We are already connected. This could be a
			// retransmission of the SYN-ACK or a SYN-ACK for the
			// first SYN.
			if (cd->st_time2.tv_sec != 0 &&
					cd->st_time2.tv_usec != 0) {
				if (ack == (cd->st_seq_client2+1)) {
					// We got another SYN in connectde state, and
					// the server is acking the new one.
					// Start statistics afresh for the connection.
					cd->st_time = cd->st_time2;
					cd->st_seq_client = cd->st_seq_client2;
					cd->synack_txmts = 0;
				} else {
					// either the server is acking the old
					// SYN, or it is a broken server.
					// Either case, we can drop the
					// packet.
					if (debug) {
						LOG_TRACE("%s:%hu > ", inet_ntoa(*ipsrc), sport);
						LOG_TRACE("%s:%hu SA SEQ:%lu,DROPPED\n", inet_ntoa(*ipdst), dport, seq);
					}
					return;
				}
			}
		}
		cd->st_seq_server = seq;
		int msecs = tvdiff_msecs(&(cd->st_time), tv);
		cd->synack_txmts++;
		if (debug) {
			// Calling inet_ntoa() twice in the same print statements will
			// muddle the ip addresses.
			LOG_TRACE("%s:%hu > ", inet_ntoa(*ipsrc), sport);
			LOG_TRACE("%s:%hu SA SEQ:%lu,MSECS:%d\n", inet_ntoa(*ipdst), dport, cd->st_seq_server, msecs);
		}
		// If this is a retransmission of the SYN|ACK, then we don't
		// want to consider this for rtt computation -- whether we
		// are on the client side or server side.
		if (cd->state == CONNECTING) {
		  if (find_rtt || (addrs.find(ipdst->s_addr) != addrs.end())) {
			// The syn|ack was destined for one of our
			// addresses.
			if (find_rtt == 0) {
				fprintf(stderr, RTT_EST_ENABLED);
			}
			find_rtt++;
			cd->st_rtt = msecs;
		  }
		}
		cd->state = CONNECTED;
	}
}

static void
process_tcp_pkt(const struct timeval *tv, u_char *hdr,
		struct in_addr *ipsrc, struct in_addr *ipdst,
		int tcplen)
{
	struct tcphdr *tcph = (struct tcphdr *)hdr;
	u_char flags = tcph->th_flags;
	bool reset = ((tcph->th_flags & TH_RST) != 0);

	if (filter_st_time.tv_sec >= tv->tv_sec) {
		LOG_DDEBUG("%s", "Dropping old pkt");
		return;
	}

	LOG_DDEBUG("TCP data offset = %d, TCP len = %d\n", tcph->th_off *4,
			tcplen);
	// If RST is set, then procses that and nothing else.
	if (reset) {
		process_end_conn(tv, tcph, ipsrc, ipdst, true, 0);
		return;
	}
	if (flags & TH_SYN) {
		if (flags & TH_ACK) {
			process_synack(tv, tcph, ipsrc, ipdst);
		} else {
			process_syn(tv, tcph, ipsrc, ipdst);
		}
	} else if (flags & TH_FIN) {
		process_end_conn(tv, tcph, ipsrc, ipdst, false,
				tcplen - tcph->th_off * 4);
	} else {
		return;
	}
}

// We output the X and Y values for a graph that shows the
// time in x axis and the number of long-lived connectins in
// Y axis. A long-lived connection is one that has been
// in ESTABLISHED state (or, our close guess of that state,
// for we count SYNRCVD state as ESTABLISHED as well).
// for longer than min_conntime msecs. We output this at
// some reasonable time intervals (for now, defined as
// every min_conntime/10 packets that we see).
static void
print_longconns(const struct timeval *tv)
{
	long long xval = tvdiff_msecs(&filter_st_time, tv);
	if (xval < 0) xval = 0;
	int yval = 0;
	connhash::const_iterator it;
	for (it = tab.begin(); it != tab.end(); it++) {
		struct conndet *cd = it->second;
		if (cd->state < CONNECTED) {
			continue;
		}
		if (tvdiff_msecs(&(cd->st_time), tv) > min_conntime) {
			yval++;
		}
	}
	printf("%lu, %f %d\n", (unsigned long)tab.size(), (float) xval/1000.0, yval);
// #ifdef __x86_64__
}

static void
process_pkt(u_char *useless, const struct pcap_pkthdr *pkthdr,
		const u_char *eth)
{
	if (done) {
		end_process();
	}
	static int  count = 0;
	u_char	    *iph, *tcph;
	//u_char	    *lh;
	u_char	    proto;
	//char	prefix[128];
	//char	srcname[48], dstname[48];
	struct	in_addr *ipsrc, *ipdst;
	const struct timeval *tv = &(pkthdr->ts);
	static int pktnum = 0;

	if (fromfile) {
		if (gottime == 0) {
			gottime++;
			trace_st_time = *tv;
		}
		trace_end_time = *tv;
	}
	if (min_conntime && ((pktnum % (min_conntime/10)) == 0)) {
		print_longconns(tv);
	}
	if (pktnum == 0) {
		// This is the first packet we are seeing. Get the time from
		// that.
		if (filter_st_time_str != NULL) {
			set_start_time(tv);
		} else {
			// Set filter_st_time to be same as trace_st_time.
			filter_st_time = trace_st_time;
			filter_st_time.tv_sec -= 1; // make sure we take in the first pkt.
		}
	}
	pktnum++;
	LOG_DDEBUG("Got packet %d:len = %d, caplen = %d\n", ++count,
			pkthdr->len, pkthdr->caplen);
	if (get_ip_hdr(eth, &iph) != 0) {
		LOG_DDEBUG("Not IP packet\n");
		return;
	}
	proto = get_proto(iph, &tcph);
	LOG_DDEBUG("Proto = %u\n", proto);
	if (proto != IPPROTO_TCP) {
		LOG_DDEBUG("Not TCP packet");
		return;
	}

	LOG_DDEBUG("FOUND TCP/IP PACKET\n");
	LOG_DDEBUG("IP hdr len = %d\n", ((struct ip *)(iph))->ip_hl * 4);
	LOG_DDEBUG("IP total len = %d\n", htons(((struct ip *)(iph))->ip_len));

	int tcplen = htons(((struct ip *)(iph))->ip_len) -
			((struct ip *)(iph))->ip_hl * 4;
	//lh = (u_char *)(tcph + sizeof (struct tcphdr));
	ipsrc = &(((struct ip *)iph)->ip_src);
	ipdst = &(((struct ip *)iph)->ip_dst);
	process_tcp_pkt(tv, tcph, ipsrc, ipdst, tcplen);
}

static int
set_filter(pcap_t *pc, char *dev, int argc, char *argv[])
{
	bpf_u_int32 mask, net;
	char errbuf[PCAP_ERRBUF_SIZE];
	int rv;
	char	port_filter[256];
	std::string filter;
	struct bpf_program bpf;

	errbuf[0] = 0;
	if ((rv = pcap_lookupnet(dev, &net, &mask, errbuf)) != 0) {
		LOG_ERROR("pcap_lookupnet:%d:%s\n", rv, errbuf);
		return (-1);
	}

	snprintf(port_filter, sizeof (port_filter), "(tcp port %d)&&((tcp[tcpflags] & (tcp-syn|tcp-fin|tcp-rst)) != 0)", port);
	filter = port_filter;
	if (argc) {
		/*
		 * User has specified additional filters. We need to 
		 * append them to the port filter we specify by default.
		 */
		filter += "&&(";
		for (int i = 0; i < argc; i++) {
			filter += argv[i];
			filter += " ";
		}
		filter += ")";
	}
	LOG_DEBUG("Setting filter to %s", filter.c_str());
	char filtchars[filter.length()+1];
	strcpy(filtchars, filter.c_str());
	if ((rv = pcap_compile(pc, &bpf, filtchars, 0, net)) != 0) {
		LOG_ERROR("pcap_compile:%d\n", rv);
		return (-1);
	}

	if ((rv = pcap_setfilter(pc, &bpf)) != 0) {
		LOG_ERROR("pcap_setfilter:%d\n", rv);
		return (-1);
	}
	return (0);
}

static void
print_duration_bucket_raw(const int i)
{
	if (i < nbuckets) {
		printf("%0lld,%0lld,",
				(long long)(i+lo_bucket) * bucket_size,
				(long long)(i+lo_bucket+1) * bucket_size);
	} else {
		printf("%0lld+,", (long long)(i+lo_bucket) * bucket_size);
	}
	printf("%0lld,%0.2f%%,", buckets[i].nconns, (float)buckets[i].nconns*100/nconns);
	if (buckets[i].nconns)  {
		printf("%0lld,%0lld,",
				buckets[i].clsize/buckets[i].nconns,
				buckets[i].srsize/buckets[i].nconns);
		if (find_rtt) {
			printf("%0lld,", buckets[i].rtt/buckets[i].nconns);
		} else {
			printf(",");
		}
		printf("%.2f\n", (float)(buckets[i].thruput)/buckets[i].nconns);
	} else {
		printf(",,,\n");
	}
}

static void
print_duration_bucket(const int i)
{
	if (i < nbuckets) {
		printf("%5lld - %-5lld ",
				(long long)(i+lo_bucket) * bucket_size,
				(long long)(i+lo_bucket+1) * bucket_size);
	} else {
		printf("%5lld+        ", (long long)(i+lo_bucket) * bucket_size);
	}
	printf("%8lld(%5.2f%%) ", buckets[i].nconns, (float)buckets[i].nconns*100/nconns);
	if (buckets[i].nconns)  {
		printf("%8lld  %8lld      ",
				buckets[i].clsize/buckets[i].nconns,
				buckets[i].srsize/buckets[i].nconns);
		if (find_rtt) {
			printf("%4lld ", buckets[i].rtt/buckets[i].nconns);
		} else {
			printf(" -   ");
		}
		printf("    %.2f\n", (float)(buckets[i].thruput)/buckets[i].nconns);
	} else {
		printf("     -         -         -\n");
	}
}

static void
print_bytes_bucket(const int i)
{
	if (raw_output) {
	    if (i < nbuckets) {
		printf("%lld,%lld,",
				(long long)(i+lo_bucket) * bucket_size,
				(long long)(i+lo_bucket+1) * bucket_size);
	    } else {
		printf("%lld+,", (long long)(i+lo_bucket) * bucket_size);
	}
	    printf("%lld,%.2f%%,", buckets[i].nconns, (float)buckets[i].nconns*100/nconns);
	    if (buckets[i].nconns)  {
		printf("%lld,%lld,",
				buckets[i].clsize/buckets[i].nconns,
				buckets[i].srsize/buckets[i].nconns);
		printf("%lld,", buckets[i].msecs/buckets[i].nconns);
		if (find_rtt) {
			printf("%lld", buckets[i].rtt/buckets[i].nconns);
		} else {
			printf(",");
		}
		printf("%.2f\n", (float)(buckets[i].thruput/buckets[i].nconns));
	    } else {
		printf(",,,,,,\n");
	    }
	} else {
	    if (i < nbuckets) {
		printf("%5lld - %-5lld ",
				(long long)(i+lo_bucket) * bucket_size,
				(long long)(i+lo_bucket+1) * bucket_size);
	    } else {
		printf("%5lld+        ", (long long)(i+lo_bucket) * bucket_size);
	    }
	    printf("%6lld(%5.2f%%)  ", buckets[i].nconns, (float)buckets[i].nconns*100/nconns);
	    if (buckets[i].nconns)  {
		printf("%8lld  %8lld   ",
				buckets[i].clsize/buckets[i].nconns,
				buckets[i].srsize/buckets[i].nconns);
		printf("%6lld     ", buckets[i].msecs/buckets[i].nconns);
		if (find_rtt) {
			printf("%4lld      ", buckets[i].rtt/buckets[i].nconns);
		} else {
			printf("   -    ");
		}
		printf("%4lld\n", (buckets[i].clsize+buckets[i].srsize)/(buckets[i].msecs+1));
	    } else {
		printf("     -         -         -         -       -\n");
	    }
	}
}

static void
print_bytes()
{
	if (report_type == REP_CLBYTES) {
		printf("ClientBytes    NumConns        AvClient  AvServer  AvDuration EstRtt  AvThruput\n");
	} else {
		printf("ServerBytes    NumConns        AvClient  AvServer  AvDuration EstRtt  AvThruput\n");
	}
	printf("     (KB) ");
	printf("                    (bytes)    (bytes)   (msecs)  (msecs)  (KB/s)\n");
	if (nconns == 0) {
		printf("No connections\n");
		return;
	}

	if (raw_output) {
		printf("===========\n");
	}
	for (int i = 0; i <= nbuckets; i++) {
		print_bytes_bucket(i);
	}
	if (raw_output) {
		printf("===========\n");
	}
	if (lo_val != -1) {
		printf("Connections for which client sent data ");
		if (hi_val == -1) {
			printf("%d+ KB:\n", lo_val);
		} else {
			printf("between %d and %d KB:\n", lo_val, hi_val);
		}
		vector<struct portdet>::const_iterator it;
		for (it = portsvec.begin(); it != portsvec.end(); it++) {
			struct portdet pd = *it;
			char ipsrc[32], ipdst[32];
			strcpy(ipsrc, inet_ntoa(pd.ipsrc));
			strcpy(ipdst, inet_ntoa(pd.ipdst));
			printf("host %s and host %s and port %d\n", ipsrc, ipdst, pd.port);
		}
	}
}

// Print the bucket range, Avg Client bytes, Avg server bytes, Avg duration
// and estimated avg RTT for the bucket.
static void
print_thruput_bucket(const int i)
{
	if (raw_output) {
	    if (i < nbuckets) {
		printf("%lld,%lld,",
				(long long)(i+lo_bucket) * bucket_size,
				(long long)(i+lo_bucket+1) * bucket_size);
	    } else {
		printf("%lld+,", (long long)(i+lo_bucket) * bucket_size);
	    }
	    printf("%lld,%.2f%%,", buckets[i].nconns, (float)buckets[i].nconns*100/nconns);
	    if (buckets[i].nconns)  {
		printf("%lld,%lld,",
				buckets[i].clsize/buckets[i].nconns,
				buckets[i].srsize/buckets[i].nconns);
		printf("%lld,", buckets[i].msecs/buckets[i].nconns);
		if (find_rtt) {
			printf("%lld,\n", buckets[i].rtt/buckets[i].nconns);
		} else {
			printf(",,\n");
		}
	    } else {
		printf(",,,\n");
	    }
	} else {
	    if (i < nbuckets) {
		printf("%4lld - %-4lld ",
				(long long)(i+lo_bucket) * bucket_size,
				(long long)(i+lo_bucket+1) * bucket_size);
	    } else {
		printf("%4lld+       ", (long long)(i+lo_bucket) * bucket_size);
	    }
	    printf("%6lld(%5.2f%%) ", buckets[i].nconns, (float)buckets[i].nconns*100/nconns);
	    if (buckets[i].nconns)  {
		printf("%8lld    %8lld    ",
				buckets[i].clsize/buckets[i].nconns,
				buckets[i].srsize/buckets[i].nconns);
		printf("%6lld        ", buckets[i].msecs/buckets[i].nconns);
		if (find_rtt) {
			printf("%4lld\n", buckets[i].rtt/buckets[i].nconns);
		} else {
			printf("   -\n");
		}
	    } else {
		printf("       -            -\n");
	    }
	}
}

static void
print_stats_v1()
{
	printf("Total Connections: %lld\nAvg Client Data: %lld bytes\n"
			"Avg Server Data: %lld bytes\n"
			"Avg conn time: %lld msecs\n",
			nconns, nconns ? clsize/nconns : 0,
			nconns ? srsize/nconns : 0,
			nconns ? conntime/nconns : 0);
	printf("Total number of SYNs: %lu (duplicates: %lu)\n", nsyns, ndupsyns);
	printf("Number of SYNs taken to establish connections: %lu\n", nsyns2estab);
	if (nconns) {
		printf("Avg no. of SYNs to establish a connection: %5.2f\n", (float)nsyns2estab/nconns);
	}
	printf("Number of unique connections that never completed: %lu\n", ndroppedconns);
	printf("Number of SYNs from incomplete connections: %lu\n", nsyns2drop);
	printf("Number of established connections in progress: %lu\n", ninprogress);
#if 0
	printf("Max syns for any connections: %lu\n", maxnsyns);
#endif
	printf("Distribution of SYNs to establsh connections (nSYNs:nConns): ");
	int nentries = synhash.size(); unsigned long i = 1;
	while (nentries) {
		nsynshash::const_iterator it = synhash.find(i);
		if (it != synhash.end()) {
			nentries--;
			printf("%lu:%lu,", i, synhash[i]);
		}
		i++;
	}
	printf("\n");
}

/**
 * Output that can be modified.
 */
static void
print_stats()
{
	printf("Start time: %s", ctime((time_t *)&(trace_st_time.tv_sec)));
	printf("End time: %s", ctime((time_t *)&(trace_end_time.tv_sec)));
	printf("Total Connections (terminated by FIN): %lld\nAvg Client Data: %lld bytes\n"
			"Avg Server Data: %lld bytes\n"
			"Avg conn duration: %lld msecs\n",
			nconns, nconns ? clsize/nconns : 0,
			nconns ? srsize/nconns : 0,
			nconns ? conntime/nconns : 0);
	printf("Avg Round Trip Time: %lld msecs\n", nconns ? total_rtt/nconns : 0);
	printf("Total number of SYNs: %lu (duplicates: %lu)\n", nsyns, ndupsyns);
	printf("Connections terminated by RESET: %lu\n", nresets);
	printf("Number of SYNs taken to establish connections: %lu\n", nsyns2estab);
	if (nconns) {
		printf("Avg no. of SYNs to establish a connection: %5.2f\n", (float)nsyns2estab/nconns);
	}
	printf("Number of unique connections dropped by the server: %lu\n", ndroppedconns);
	printf("Number of SYNs from incomplete connections: %lu\n", nsyns2drop);
	printf("Number of established connections in progress: %lu (%lu may have been discarded by the client)\n", ninprogress, ndiscarded);
#if 0
	printf("Max syns for any connections: %lu\n", maxnsyns);
#endif
	printf("Number of connections in closing state: %lu\n", nclosing);
	printf("Distribution of SYNs to establsh connections (nSYNs:nConns): ");
	int nentries = synhash.size(); unsigned long i = 1;
	while (nentries) {
		nsynshash::const_iterator it = synhash.find(i);
		if (it != synhash.end()) {
			nentries--;
			printf("%lu:%lu,", i, synhash[i]);
		}
		i++;
	}
	printf("\n\n");
	if (report_type == REP_THRUPUT) {
		print_thruput();
	} else if (report_type == REP_CLBYTES || report_type == REP_SRBYTES) {
		print_bytes();
	} else {    // default is duration
		print_duration();
	}
}

static void
print_thruput()
{
	printf("Throughput      NumConns    AvgClient   AvgServer  AvgDuration   EstRTT\n");
	printf("   KB/s   ");
	printf("                   (bytes)     (bytes)     (msecs)    (msecs)\n");
	if (nconns == 0) {
		printf("No connections\n");
		return;
	}
	if (raw_output) {
		printf("===========\n");
	}

	for (int i = 0; i <= nbuckets; i++) {
		print_thruput_bucket(i);
	}
	if (raw_output) {
		printf("===========\n");
	}
	if (lo_val != -1) {
		printf("Connections for which throuput was ");
		if (hi_val == -1) {
			printf("%d+ KB/sec:\n", lo_val);
		} else {
			printf("between %d and %d KB/sec:\n", lo_val, hi_val);
		}
		vector<struct portdet>::const_iterator it;
		for (it = portsvec.begin(); it != portsvec.end(); it++) {
			struct portdet pd = *it;
			char ipsrc[32], ipdst[32];
			strcpy(ipsrc, inet_ntoa(pd.ipsrc));
			strcpy(ipdst, inet_ntoa(pd.ipdst));
			printf("host %s and host %s and port %d\n", ipsrc, ipdst, pd.port);
		}
	}
}

static void
print_duration() {
	printf("  Duration       NumConns        AvClient    AvServer   EstRtt  AvThruput\n");
	printf("  (msecs)                        (bytes)     (bytes)    (msecs)  (KB/s)\n");
	if (nconns == 0) {
		printf("No connections\n");
		return;
	}
	if (raw_output) {
		printf("===========\n");
	}
	for (int i = 0; i <= nbuckets; i++) {
		if (raw_output) {
			print_duration_bucket_raw(i);
		} else {
			print_duration_bucket(i);
		}
	}
	if (raw_output) {
		printf("===========\n");
	}
	if (lo_val != -1) {
		printf("Connections for which duration was ");
		if (hi_val == -1) {
			printf("%d+ msecs:\n", lo_val);
		} else {
			printf("between %d and %d msecs:\n", lo_val, hi_val);
		}
		vector<struct portdet>::const_iterator it;
		for (it = portsvec.begin(); it != portsvec.end(); it++) {
			struct portdet pd = *it;
			char ipsrc[32], ipdst[32];
			strcpy(ipsrc, inet_ntoa(pd.ipsrc));
			strcpy(ipdst, inet_ntoa(pd.ipdst));
			printf("host %s and host %s and port %d\n", ipsrc, ipdst, pd.port);
		}
	}
}

static void
print_stats_experimental()
{
	connhash::iterator it;
	if (min_conntime) {
		print_longconns(&trace_end_time);
		printf("Connections in Progress for longer than %d msecs:\n",
			min_conntime);

		for (it = tab.begin(); it != tab.end(); it++) {
			struct conndet *cd = it->second;
			if (cd->state >= CONNECTED) {
				int duration = tvdiff_msecs(&(cd->st_time), &trace_end_time);
				if (duration > min_conntime) {
					printf("%d(%d):host %s and port %d\n",
						duration, cd->synack_txmts,
						inet_ntoa(cd->synsender), cd->port);
				}
			}
		}
	}

	printf("Connections without SYN|ACK:\n");

	for (it = tab.begin(); it != tab.end(); it++) {
		struct conndet *cd = it->second;
		if (cd->state < CONNECTED) {
			printf("NOSYNACK:host %s and port %d\n",
					inet_ntoa(cd->synsender), cd->port);
		}
	}
}

// Do the absolute minimum in signal handlers to avoid core.
static void
sighandler(int sig)
{
	if (dumper) {
		end_process();
	}
	done++;
}

static void
end_process()
{
	struct pcap_stat ps;

	if (pcap_stats(pc, &ps) == 0) {
		fprintf(stderr, "%u Packets received\n", ps.ps_recv);
		fprintf(stderr, "%u Packets dropped\n", ps.ps_drop);
	}
	pcap_close(pc);
	if (dumper) {
		pcap_dump_close(dumper);
		exit(0);
	}
	LOG_DDEBUG("Hash has %u conns left\n", tab.size());
	connhash::iterator it;
	for (it = tab.begin(); it != tab.end(); it++) {
		struct conndet *cd = it->second;
		if (cd->state < CONNECTED) {
			// this is a dropped connection
			ndroppedconns++;
			nsyns2drop += cd->nsyns;
		} else {
			ninprogress++;
			if (cd->state == CLOSING) {
				nclosing++;
			}
			if (cd->synack_txmts >= MAX_SYNACKS) {
				// SYN|ACK was sent more than the max times
				// it is done with syncache. May be TCP just
				// dropped the connection altogether. We
				// can't say for sure, though.
				ndiscarded++;
			}
		}
	}

	//long long trace_end_time = ysys_get_usec();
	//double secs = (double)(trace_end_time - st_time)/1000000;
	if (!fromfile) {
		gettimeofday(&trace_end_time, NULL);
	}
	double secs = (double)tvdiff_msecs(&filter_st_time, &trace_end_time)/1000;
	switch (output_version) {
	case OUTPUT_VERSION_1:
		printf("Results of monitoring port %d for %f seconds\n", port, secs);
		print_stats_v1();
		break;
	case OUTPUT_EXPERIMENTAL:
		print_stats_experimental();
		break;
	default:
		printf("Results of monitoring port %d for %f seconds\n", port, secs);
		print_stats();
		break;
	}
	exit(0);
}

// If we are looking to report by the number of bytes that the server or
// client sent, and we have an upper limit on the size, then we can adjust so
// that we don't report buckets with 0 data unnecessarily.
static void
adjust_nbuckets()
{
	if (report_type == REP_CLBYTES) {
		if (max_clnt_reqsize) {
			int blo = min_clnt_reqsize/bucket_size/1024;
			int bhi = max_clnt_reqsize/bucket_size/1024;
			if (bhi - blo + 1 < nbuckets) {
				nbuckets = bhi - blo + 1;
			}
		}
	} else if (report_type == REP_SRBYTES) {
		if (max_srvr_rspsize) {
			int blo = min_srvr_rspsize/bucket_size/1024;
			int bhi = max_srvr_rspsize/bucket_size/1024;
			if (bhi - blo + 1 < nbuckets) {
				nbuckets = bhi - blo + 1;
			}
		}
	}
}

int
main(int argc, char *argv[])
{
	int	ch;
	char	*cmd = argv[0];
	char	*dev = NULL;
	char rfile[MAXPATHLEN] = {0};
	char wfile[MAXPATHLEN] = {0};
	unsigned int runtime = 60;   // seconds
	report_type = REP_DURATION;	// default report type

	while ((ch = getopt(argc, argv, "I:Rc:m:V:w:x:X:y:Y:t:n:s:p:r:i:dTD:SPC")) != -1) {
		switch (ch) {
		case 'd':
			debug++;
			break;
		case 'i':
			if (dev == NULL) {
				dev = optarg;
			} else {
				usage(cmd);
			}
			break;
		case 't':
			runtime = atoi(optarg);
			break;
		case 'R':
			raw_output = true;
			break;
		case 'r':
			if (rfile[0] == 0) {
				snprintf(rfile, sizeof (rfile), "%s", optarg);
			} else {
				usage(cmd);
			}
			break;
		case 'n':
			nbuckets = atoi(optarg);
			break;
		case 's':
			bucket_size = atoi(optarg);
			break;
		case 'X':
			max_srvr_rspsize = atoi(optarg);
			break;
		case 'x':
			max_clnt_reqsize = atoi(optarg);
			break;
		case 'Y':
			min_srvr_rspsize = atoi(optarg);
			break;
		case 'y':
			min_clnt_reqsize = atoi(optarg);
			break;
		case 'p':
			port = atoi(optarg);
			break;
		case 'T':
			find_rtt++;
			break;
		case 'D':
			lo_val = atoi(optarg);
			break;
		case 'w':
			if (wfile[0] == 0) {
				snprintf(wfile, sizeof (wfile), "%s", optarg);
			} else {
				usage(cmd);
			}
			break;
		case 'V':
			output_version = atoi(optarg);
			break;
		case 'm':
			min_conntime = atoi(optarg);
			break;
		case 'c':
			min_conn_attempts = atoi(optarg);
			break;
		case 'C':
			if (report_type == REP_DURATION) {
				report_type = REP_CLBYTES;
			} else {
				fprintf(stderr, "Only one of -S,-P or -C please\n");
				usage(cmd);
			}
			break;
		case 'S':
			if (report_type == REP_DURATION) {
				report_type = REP_SRBYTES;
			} else {
				fprintf(stderr, "Only one of -S,-P or -C please\n");
				usage(cmd);
			}
			break;
		case 'P':
			if (report_type == REP_DURATION) {
				report_type = REP_THRUPUT;
			} else {
				fprintf(stderr, "Only one of -S,-P or -C please\n");
				usage(cmd);
			}
			break;
		case 'I':
			filter_st_time_str = optarg;
			break;
		case '?':
		default:
			usage(cmd);
			break;
		}
	}

	if (filter_st_time_str) {
		struct tm tm;
		if (!str_2_tm(&tm)) {
			usage(cmd);
		}
	}

	if (min_conntime && (output_version != OUTPUT_EXPERIMENTAL)) {
		printf("%s: illegal option -- m\n", cmd);
		usage(cmd);
	}

	if (wfile[0] == 0) {
		if (nbuckets == 0) {
			nbuckets = NBUCKETS;
		}
		if (bucket_size == 0) {
			bucket_size = BUCKET_SIZE;
		}
	}

	if (lo_val < bucket_size * nbuckets) {
		hi_val = lo_val + bucket_size;
	}

	if (min_clnt_reqsize && max_clnt_reqsize && min_clnt_reqsize >= max_clnt_reqsize) {
		fprintf(stderr, "Client requests < %ld and > %ld?\n",
				max_clnt_reqsize, min_clnt_reqsize);
		usage(cmd);
		exit(1);
	}
	if (min_srvr_rspsize && max_srvr_rspsize && min_srvr_rspsize >= max_srvr_rspsize) {
		fprintf(stderr, "Server responses < %ld and > %ld?\n",
				max_srvr_rspsize, min_srvr_rspsize);
		usage(cmd);
		exit(1);
	}

	if (min_clnt_reqsize && report_type == REP_CLBYTES) {
		lo_bucket = min_clnt_reqsize/1024/bucket_size;
	}
	if (min_srvr_rspsize && report_type == REP_SRBYTES) {
		lo_bucket = min_srvr_rspsize/1024/bucket_size;
	}

	adjust_nbuckets();

	argc -= optind;
	argv += optind;

	if (port == 0) {
		fprintf(stderr, "Port must be specified\n");
		usage(cmd);
	}
	if (wfile[0] == 0) {
		if (nbuckets <= 0 || runtime <= 0 || bucket_size <= 0) {
			fprintf(stderr, "Illegal value for options\n");
			exit(1);
		}
		buckets = (struct bucket *)calloc(nbuckets + 1, sizeof (struct bucket));
		if (buckets == NULL) {
			perror("malloc:");
			exit(1);
		}
	}

	if ((dev == NULL) && (rfile[0] == 0)) {
		dev = find_dev();
		if (dev == NULL) {
			LOG_ERROR("No devices found\n");
			LOG_ERROR("Try the command with a 'sudo' prefix\n");
			usage(cmd);
		}
	}

	pc = open_pcap(rfile, dev, 256, 0, 1000);
	if (pc == NULL) {
		exit(1);
	}

	if (set_filter(pc, dev, argc, argv) != 0) {
		exit (1);
	}

	datalink = pcap_datalink(pc);
	switch (datalink) {
	case DLT_NULL:
		break;
	case DLT_EN10MB:
		break;
	default:
		printf("Unknown datalink type: %d\n", datalink);
		exit(1);
		break;
	}

	if (rfile[0] == 0) {
		// We are not reading from a file
		signal(SIGINT, sighandler);
		signal(SIGALRM, sighandler);
		alarm(runtime);
		gettimeofday(&trace_st_time, NULL);
	} else {
		fromfile = true;
	}

	if (wfile[0] != 0) {
		dumper = pcap_dump_open(pc, wfile);
		if (dumper == NULL) {
			LOG_ERROR("%s:pcap_dump_open:%s", wfile, strerror(errno));
			exit(1);
		}
	}
	if (dumper == NULL) {
		if (max_clnt_reqsize) {
			printf("Considering connections where client sends < %lu bytes to the server\n",
				max_clnt_reqsize);
		} 
		if (max_srvr_rspsize) {
			printf("Considering connections where server sends < %lu bytes to the client\n",
				max_srvr_rspsize);
		} 
		if (min_clnt_reqsize) {
			printf("Considering connections where clients sends > %lu bytes to the server\n", min_clnt_reqsize);
		} 
		if (min_srvr_rspsize) {
			printf("Considering connections where server sends > %lu bytes to the client\n", min_srvr_rspsize);
		}
		if (find_rtt) {
			if (rfile[0] == 0) {
				fprintf(stderr, RTT_EST_ENABLED "Estimates will be wrong if this machine is the server for port %d\n", port);
			} else {
				fprintf(stderr, RTT_EST_ENABLED "Estimates will be wrong if this trace was captured on the server for port %d\n", port);
			}
		}
	}
	if (dumper) {
		if (debug) {
			fprintf(stderr, "-d ignored\n");
		}
		if (nbuckets) {
			fprintf(stderr, "-n ignored\n");
		}
		if (bucket_size) {
			fprintf(stderr, "-s ignored\n");
		}
		if (max_srvr_rspsize) {
			fprintf(stderr, "-X ignored\n");
		}
		if (max_clnt_reqsize) {
			fprintf(stderr, "-x ignored\n");
		}
		if (min_srvr_rspsize) {
			fprintf(stderr, "-Y ignored\n");
		}
		if (min_clnt_reqsize) {
			fprintf(stderr, "-y ignored\n");
		}
		if (lo_val != -1) {
			fprintf(stderr, "-D ignored\n");
		}
		if (find_rtt) {
			fprintf(stderr, "-T ignored\n");
		}
		if (raw_output) {
			fprintf(stderr, "-R ignored\n");
		}
		if (output_version) {
			fprintf(stderr, "-V ignored\n");
		}
		pcap_loop(pc, -1, pcap_dump, (u_char *)dumper);
	} else {
		if (fromfile) {
			pcap_loop(pc, -1, process_pkt, NULL);
		} else {
			while (1) {
				pcap_dispatch(pc, 128, process_pkt, NULL);
				if (done) {
					end_process();
					break;
				}
			}
		}
	}

	if (rfile[0] != 0) {
		end_process();
	}

	exit(0);
}
