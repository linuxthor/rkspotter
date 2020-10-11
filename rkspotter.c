/* 
 * rkspotter
 *
 * Copyright (c) 2020 linuxthor.
 * 
 * This program is free software: you can redistribute it and/or modify  
 * it under the terms of the GNU General Public License as published by  
 * the Free Software Foundation, version 3. Or give it to the rag and 
 * bone man because I love eels.
 *
 * This program is distributed in the hope that it will be useful, but 
 * WITHOUT ANY WARRANTY; without even the implied warranty of your 
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU 
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License 
 * along with this program. If not, see <http://www.gnu.org/licenses/>
 */

#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/uio.h>  
#include <linux/namei.h>
#include <linux/mount.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/uaccess.h>
#include <linux/pagemap.h>
#include <linux/kprobes.h>
#include <linux/sched/task.h>

// sys_call_table
unsigned long *sct;
// __access_remote_vm 
static int (*arvm)(struct task_struct *tsk, struct mm_struct *mm, unsigned long addr, 
                                                          void *buf, int len, int write);
 
void *memsrch(const void *s1, size_t len1, const void *s2, size_t len2)
{
    if (!len2)
    {
        return (void *)s1;
    }
    while (len1 >= len2) 
    {
        len1--;
        if (!memcmp(s1, s2, len2))
        {
            return (void *)s1;
        }
        s1++;
    }
    return NULL;
}

// I think this is a pretty unclean way to get this information but the code is small ;) 
int get_filesz_by_path(const char *pathname)
{
    struct path path;
    struct inode *inode;
    int size;

    size=-1;
    if (kern_path(pathname, 0, &path) == 0)
    {
        inode = path.dentry->d_inode;
        size = inode->i_size;
        mark_inode_dirty_sync(inode);
        path_put(&path);
    }
    return size;
}

static struct kprobe sct_kp = { 
};
unsigned long *kprobe_find_sct(void)
{
    unsigned long *table; 

    sct_kp.symbol_name = "sys_call_table";
    register_kprobe(&sct_kp);
    table = (void *)sct_kp.addr;
    if(table != 0)
    {
        //printk("rks: sys_call_table at %px\n",(void *)table);
    } 
    else
    {
        //printk("rks: sys_call_table not found\n"); 
    }
    return table;
}

static struct kprobe arvm_kp = { 
};
unsigned long *kprobe_find_arvm(void)
{
    unsigned long *access_rem_vm; 

    arvm_kp.symbol_name = "__access_remote_vm";
    if(register_kprobe(&arvm_kp) == 0)
             unregister_kprobe(&arvm_kp); 
    access_rem_vm = (void *)arvm_kp.addr;
    if(access_rem_vm != 0)
    {
        //printk("rks: __access_remote_vm at %px\n",(void *)access_rem_vm);
    } 
    else
    {
        //printk("rks: __access_remote_vm not found\n"); 
    }
    return access_rem_vm;
}

int lkm_code_check(unsigned long *addr, int len)
{
    // code signatures.. 
    //
    // 0f 22 c0            mov    %rax,%cr0
    char cr0_rax[3] = {'\x0f','\x22','\xc0'};

    if(memsrch(addr, len, cr0_rax, 3) != 0)
    {
        return -1; 
    }
    return 0; 
}

int lkm_data_check(unsigned long *addr, int len)
{
    int x;

    // data signatures..
    //
    char *data_str[24] = {
    // strings associated with (unmodified) reptile rootkit    
      "/reptile/reptile","KHOOK_","is_proc_invisible",
    // strings associated with (unmodified) rootfoo rootkit
      "ROOTKIT syscall_table", "ROOTKIT sys_call_table", "un_hijack_execve",
    // strings associated with (unmodified) sutekh rootkit
      "Giving r00t", "[?] SCT:", "Example Rootkit",
    // strings associated with (unmodified) lilyofthevalley rootkit
      "givemeroot"," lilyofthevalley"," u want to hide",
    // strings associated with (unmodified) diamorphine rootkit
      "diamorphine_","m0nad","LKM rootkit",
    // strings associated with (unmodified) honeypot bears rootkit
      "_backdoor_user","/home/haxor","/etc/secretshadow",
    // strings associated with (unmodified) nuk3gh0stbeta rootkit
      "hide pid command","hide file command","asm_hook_remove_all",
    // strings associated with generic rootkits in general
      "r00tkit","r00tk1t","module_hide"
    };

    // data check.. 
    for (x = 0; x < (sizeof(data_str) / sizeof(char *)); x++)
    {
        if(memsrch(addr, len, (char *)data_str[x], strlen((char *)data_str[x])) != 0)
        {
            return -1;
        }
    }
    return 0;
}

void look_for_lkm(void)
{
    struct module *mahjool; 
    struct kobject kobj; 
    unsigned long addy; 

    for (addy = MODULES_VADDR; addy < MODULES_END; (addy = (addy + 4096)))
    { 
        // does this memory region belong to a module? 
        if(__module_address(addy) != 0)
        { 
            mahjool = __module_address(addy);

            //// Here are some LKM checks..
            ///  ==========================
            ///
            ///  simple integrity checks first.. 
            ///
            //   we assume that all LKM were minted together in a McFactory and should look alike and 
            //   be in a good and orderly state so we check if this LKM has anything suspect going on 
            //   that might show it's 'not like the others' 

            //// Hidden modules: 
            // 
            //   some modules are hidden from /proc/modules & tools like 'lsmod' using code like:
            //
            //      list_del_init(&__this_module.list);   
            //
            //   list_del_init simply juggles some pointers about which we can look for.. 
            // 
            if(mahjool->list.next == mahjool->list.prev)
            {
                 printk("rks: module (@%px - size: %d / %s) suspect list ptrs\n",
                                                                    (void *)mahjool->core_layout.base, 
                                                                           mahjool->core_layout.size,
                                                                                        mahjool->name);
            }

            //  some modules are hidden (/proc & lsmod etc) with code like: 
            //
            //    list_del(&THIS_MODULE->list); 
            //   
            //  list_del marks prev and next pointers with a (non null) 'poison' value
            //
            if((mahjool->list.next == LIST_POISON1) || (mahjool->list.prev == LIST_POISON2)) 
            {
                printk("rks: module (@%px - size: %d / %s) has poison pointer in list\n", 
                                                                      (void *)mahjool->core_layout.base,
                                                                            mahjool->core_layout.size,
                                                                                        mahjool->name); 
            }

            //
            //   some modules are further hidden from sysfs (/sys/modules/) with code like:
            //
            //      kobject_del(&THIS_MODULE->mkobj.kobj);
            //
            //   the underlying __kobject_del does a bunch of cleanup and sets a marker so lets look for 
            //   the marker.. 
            // 
            kobj = mahjool->mkobj.kobj; 
            if(kobj.state_in_sysfs == 0)
            {
                printk("rks: module (@%px - size: %d / %s) suspect sysfs state\n", 
                                                             (void *)mahjool->core_layout.base,
                                                                     mahjool->core_layout.size,
                                                                                 mahjool->name);
            }

            //// Structure misc weirdness: 
            //  
            //   something that a couple of rootkits do is to:  
            //
            //      kfree(THIS_MODULE->sect_attrs);
            //      THIS_MODULE->sect_attrs = NULL;
            //
            //   (or possibly the same/similar with the notes_attrs)
            // 
            if((mahjool->sect_attrs == NULL) || (mahjool->notes_attrs == NULL))
            {
                printk("rks: module (@%px - size: %d / %s)  suspect attrs state\n", 
                                                              (void *)mahjool->core_layout.base,
                                                                      mahjool->core_layout.size, 
                                                                                  mahjool->name);
            }

            //// now some code check..
            //
            // TODO => add more
            //
	    if(lkm_code_check(mahjool->core_layout.base, mahjool->core_layout.text_size) != 0)
	    {
		printk("rks: module %s contains suspect instruction sequence\n", mahjool->name);
	    }

            //// now some data checks..
            // 
            if(lkm_data_check((mahjool->core_layout.base + mahjool->core_layout.text_size), 
                                  (mahjool->core_layout.ro_size - mahjool->core_layout.text_size)) != 0)
            {
                // we filter out our own module by comparing address 
                if(THIS_MODULE->core_layout.base != mahjool->core_layout.base)
                {
                    printk("rks: module %s contains suspect data sequence\n", mahjool->name);
                }
            }
 
            addy = (addy + mahjool->core_layout.size);
        }
    
    }   
    //
    // check sys_call_table next
    //                                
    if(sct != 0)
    {
        // check if sys_call_table contains any pointers to a module for a couple
        // of often hooked functions.. 
        if((sct[__NR_open] > MODULES_VADDR) && 
                             (sct[__NR_open] < MODULES_END))
        {
            printk("rks: syscall table sys_open entry points to a module!\n");
        }
        if((sct[__NR_getdents] > MODULES_VADDR) && 
                             (sct[__NR_getdents] < MODULES_END))
        {
            printk("rks: syscall table sys_getdents entry points to a module!\n");
        }
        if((sct[__NR_getdents64] > MODULES_VADDR) && 
                             (sct[__NR_getdents64] < MODULES_END))
        {
            printk("rks: syscall table sys_getdents64 entry points to a module!\n");
        }
        if((sct[__NR_readlink] > MODULES_VADDR) && 
                              (sct[__NR_readlink] < MODULES_END))
        {
            printk("rks: syscall table sys_readlink entry points to a module!\n");
        }
    }
}

void look_for_userspace(void)
{
    int x;
    int pmd = PID_MAX_DEFAULT; 
    struct task_struct *ts; 
    char tsk[TASK_COMM_LEN]; 
    struct mm_struct *emem;
    void *yabba;
    char *ldp = "LD_PRELOAD";
    //
    // a check for userspace rootkits working via LD_PRELOAD in the environment 
    if(arvm != 0)
    {
        for(x = 2; x < pmd; x++)
        {
            ts = pid_task(find_vpid(x), PIDTYPE_PID); 
            if(ts != 0)
            {
                get_task_comm(tsk, ts);
                task_lock(ts);
                if(ts->mm != 0)
                {
                    emem = ts->mm;

                    // some tools (e.g HORSE PILL) use processes that fake being kernel threads 
                    if(tsk[0] == '[')
                    { 
                        printk("rks: process %d (%s) appears to be a fake kernel thread\n",x,tsk);
                    }
                   
                    // we don't get out of bed for less than 16 bytes 
                    if((emem->env_end - emem->env_start) > 16)
                    {
                        yabba = kmalloc((emem->env_end - emem->env_start), GFP_KERNEL);

                        // fetch the environment/envp for the process
                        arvm(ts, emem, emem->env_start, yabba, (emem->env_end - emem->env_start),  
                                                                                       FOLL_FORCE);
                        // search for the LD_PRELOAD environment variable 
                        if(memsrch(yabba, (emem->env_end - emem->env_start), ldp, strlen(ldp)) != 0)
                        {
                            printk("rks: process %d (%s) has LD_PRELOAD environment var\n", x, tsk);
                        }

                        kfree(yabba);
                    }
                }
                task_unlock(ts);
            }
        }
    }
    else
    {
        printk("rks: not found __access_remote_vm so skipping environment check\n");
    }

    // 
    //   there may be entries in a global ld preload file
    // 
    if (get_filesz_by_path("/etc/ld.so.preload") > 0)
    {
        printk("rks: found /etc/ld.so.preload exists and is not empty\n");
    }
}

int init_module(void)
{
    // use kprobe hack to find a couple of addresses first
    sct = kprobe_find_sct();
    arvm = (void *)kprobe_find_arvm();

    look_for_lkm();
    look_for_userspace();
 
    return 0;
}

void cleanup_module(void)
{

}

MODULE_AUTHOR("linuxthor");
MODULE_LICENSE("GPL");
