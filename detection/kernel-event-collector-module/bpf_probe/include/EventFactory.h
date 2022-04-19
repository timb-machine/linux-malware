/* Copyright (c) 2021 VMWare, Inc. All rights reserved. */
/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */

#pragma once

#include "bcc_sensor.h"

#include <memory>
#include <string.h>

namespace cb_endpoint {
namespace bpf_probe {

    class EventFactory
    {
    public:
        using Event = std::unique_ptr<char[]>;

        static void InitHeader(
            data_header &header,
            uint8_t      type,
            uint8_t      state,
            uint64_t     event_time,
            uint32_t     pid,
            uint32_t     parent_pid)
        {
            header.type = type;
            header.state = state;
            header.event_time = event_time;

            header.tid = pid;
            header.pid = pid;
			header.ppid = parent_pid;
            header.uid = 0;
		    header.mnt_ns = 0;
        }

        static Event Data(
            uint8_t      type,
            uint8_t      state,
            uint64_t     event_time,
            uint32_t     pid,
            uint32_t     parent_pid)
        {
            Event event(new char[sizeof(struct data)]);

            if (event)
            {
                auto data = static_cast<struct data *>((void*)event.get());
                InitHeader(
                    data->header, type, state,
                    event_time, pid, parent_pid);
            }
            return event;
        }

        static Event Fork(
            uint64_t     event_time,
            uint32_t     pid,
            uint32_t     parent_pid)
        {
            return Data(EVENT_PROCESS_CLONE, PP_NO_EXTRA_DATA, event_time, pid, parent_pid);
        }

        static Event Exit(
            uint64_t     event_time,
            uint32_t     pid,
            uint32_t     parent_pid)
        {
            return Data(EVENT_PROCESS_EXIT, PP_NO_EXTRA_DATA, event_time, pid, parent_pid);
        }

        static Event ExecArg(
            uint64_t     event_time,
            uint32_t     pid,
            uint32_t     parent_pid,
            const char  *arg)
        {
            return Path(
                EVENT_PROCESS_EXEC_ARG,
                PP_ENTRY_POINT,
                event_time,
                pid,
                parent_pid,
                arg);
        }

        static Event ExecArgEnd(
            uint64_t     event_time,
            uint32_t     pid,
            uint32_t     parent_pid)
        {
            return Data(EVENT_PROCESS_EXEC_ARG, PP_FINALIZED, event_time, pid, parent_pid);
        }

        static Event ExecPathStart(
            uint64_t     event_time,
            uint32_t     pid,
            uint32_t     parent_pid,
            uint32_t     device,
            uint64_t     inode,
            uint64_t     flags = 0,
            uint64_t     prot = 0)
        {
            return File(
                EVENT_PROCESS_EXEC_PATH,
                event_time,
                pid,
                parent_pid,
                device,
                inode,
                flags,
                prot);
        }

        static Event ExecPath(
            uint64_t     event_time,
            uint32_t     pid,
            uint32_t     parent_pid,
            const char  *path)
        {
            return Path(
                EVENT_PROCESS_EXEC_PATH,
                PP_PATH_COMPONENT,
                event_time,
                pid,
                parent_pid,
                path);
        }

        static Event ExecPathDone(
            uint64_t     event_time,
            uint32_t     pid,
            uint32_t     parent_pid)
        {
            return Data(EVENT_PROCESS_EXEC_PATH, PP_FINALIZED, event_time, pid, parent_pid);
        }

        static Event ExecResult(
            uint64_t     event_time,
            uint32_t     pid,
            uint32_t     parent_pid,
            int          retval)
        {
            Event event(new char[sizeof(struct exec_data)]);

            if (event)
            {
                auto data = static_cast<struct exec_data *>((void*)event.get());
                InitHeader(
                    data->header, EVENT_PROCESS_EXEC_RESULT, PP_NO_EXTRA_DATA,
                    event_time, pid, parent_pid);

                data->retval = retval;
            }
            return event;
        }

        static Event File(
            uint8_t      type,
            uint64_t     event_time,
            uint32_t     pid,
            uint32_t     parent_pid,
            uint32_t     device,
            uint64_t     inode,
            uint64_t     flags = 0, // MMAP only
            uint64_t     prot = 0)
        {
            Event event(new char[sizeof(struct file_data)]);

            if (event)
            {
                auto data = static_cast<struct file_data *>((void*)event.get());
                InitHeader(
                    data->header, type, PP_ENTRY_POINT,
                    event_time, pid, parent_pid);

                data->device = device;
                data->inode = inode;
                data->flags = flags;
                data->prot = prot;
            }
            return event;
        }

        static Event FilePath(
            uint8_t      type,
            uint64_t     event_time,
            uint32_t     pid,
            uint32_t     parent_pid,
            const char  *path)
        {
            return Path(
                type,
                PP_PATH_COMPONENT,
                event_time,
                pid,
                parent_pid,
                path);
        }

        static Event FilePathDone(
            uint8_t      type,
            uint64_t     event_time,
            uint32_t     pid,
            uint32_t     parent_pid)
        {
            return Data(type, PP_FINALIZED, event_time, pid, parent_pid);
        }

        static Event Path(
            uint8_t      type,
            uint8_t      state,
            uint64_t     event_time,
            uint32_t     pid,
            uint32_t     parent_pid,
            const char  *path)
        {
            Event event(new char[sizeof(struct path_data)]);

            if (event)
            {
                auto data = static_cast<struct path_data *>((void*)event.get());
                InitHeader(
                    data->header, type, state,
                    event_time, pid, parent_pid);

                data->fname[0] = 0;
                if (path)
                {
                    strncat(data->fname, path, MAX_FNAME);
                }
            }
            return event;
        }

        static Event Dns(
            uint64_t       event_time,
            uint32_t       pid,
            uint32_t       parent_pid,
            uint8_t        state,
            std::string    &dns,
            uint32_t       name_len)
        {
            if (dns.size() > DNS_SEGMENT_LEN)
            {
                return nullptr;
            }

            Event event(new char[sizeof(struct dns_data)]);

            if (event)
            {
                auto data = static_cast<struct dns_data *>((void*)event.get());
                InitHeader(
                    data->header, EVENT_NET_CONNECT_DNS_RESPONSE, state,
                    event_time, pid, parent_pid);

                memcpy(data->dns, dns.c_str(), dns.size());
                data->name_len = name_len;
            }
            return event;
        }

        static Event Net(
            uint8_t      type,
            uint64_t     event_time,
            uint32_t     pid,
            uint32_t     parent_pid,
            uint16_t     ipver,
            uint16_t     protocol,
            uint32_t     local_addr[4],
            uint16_t     local_port,
            uint32_t     remote_addr[4],
            uint16_t     remote_port)
        {
            Event event(new char[sizeof(struct net_data)]);

            if (event)
            {
                auto data = static_cast<struct net_data *>((void*)event.get());
                InitHeader(
                    data->header, type, PP_NO_EXTRA_DATA,
                    event_time, pid, parent_pid);

                data->ipver = ipver;
                data->protocol = protocol;
                data->local_port = local_port;
                data->remote_port = remote_port;

                memcpy(&data->local_addr, &local_addr, sizeof(data->local_addr));
                memcpy(&data->remote_addr, &remote_addr, sizeof(data->remote_addr));
            }
            return event;
        }
    };

}}
