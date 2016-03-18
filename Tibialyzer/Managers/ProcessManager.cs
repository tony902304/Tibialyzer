using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Drawing.Imaging;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;
using System.Numerics;
using System.IO;
using System.Runtime.InteropServices;
using System.Threading;
using System.Net;
using System.Text.RegularExpressions;
using System.Data.SQLite;


namespace Tibialyzer {
    class ProcessManager {
        public static string TibiaClientName = "Tibia";
        public static int TibiaProcessId = -1;

        public static void Initialize() {
            TibiaClientName = SettingsManager.settingExists("TibiaClientName") ? SettingsManager.getSettingString("TibiaClientName") : TibiaClientName;
        }

        public static Process GetTibiaProcess() {
            Process[] p = GetTibiaProcesses();
            if (p == null || p.Length == 0) return null;
            return p[0];
        }

        public static Process[] GetTibiaProcesses() {
            if (TibiaProcessId >= 0) {
                Process[] ids = Process.GetProcesses();
                for (int i = 0; i < ids.Length; ++i) {
                    if (ids[i].Id == TibiaProcessId) {
                        return new Process[1] { ids[i] };
                    }
                }

                TibiaProcessId = -1;
            }
            Process[] p = Process.GetProcessesByName(TibiaClientName);
            if (p.Length > 0) {
                if (TibiaClientName.Contains("flash", StringComparison.OrdinalIgnoreCase)) {
                    return p;
                }
                return new Process[1] { p[0] };
            }
            return null;
        }

        public static void DetectFlashClient() {
            foreach (Process p in Process.GetProcesses()) {
                if (p.ProcessName.Contains("flash", StringComparison.OrdinalIgnoreCase)) {
                    TibiaClientName = p.ProcessName;
                    TibiaProcessId = -1;
                    break;
                }
            }
        }


        const int PROCESS_QUERY_INFORMATION = 0x0400;
        const int MEM_COMMIT = 0x00001000;
        const int PAGE_READWRITE = 0x04;
        const int PROCESS_WM_READ = 0x0010;

        [DllImport("kernel32.dll")]
        public static extern IntPtr OpenProcess(int dwDesiredAccess, bool bInheritHandle, int dwProcessId);
        [DllImport("kernel32.dll")]
        public static extern bool ReadProcessMemory(int hProcess, int lpBaseAddress, byte[] lpBuffer, int dwSize, ref int lpNumberOfBytesRead);

        public static void SelectProcess(Process process) {
            TibiaClientName = process.ProcessName;
            TibiaProcessId = process.Id;
            SettingsManager.setSetting("TibiaClientName", TibiaClientName);

            int currentAddress;
            int processHandle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_WM_READ, false, process.Id).ToInt32();

            Console.WriteLine("Proccess -Name: {0} -Id: {1} ", process.ProcessName, process.Id);

            currentAddress = process.MainModule.BaseAddress.ToInt32();
            Console.WriteLine("-BaseAddress: {0:X}", currentAddress);

            currentAddress += 0x534970; //magical offset that will get you to special place...
            Console.WriteLine("-OffsetAddress: {0:X}", currentAddress);

            currentAddress = getPointer(processHandle, currentAddress);
            Console.WriteLine("-Pointer1: {0:X}", currentAddress);

            currentAddress = getPointer(processHandle, currentAddress + 0x24);
            Console.WriteLine("-Pointer2: {0:X}", currentAddress);

            currentAddress = getPointer(processHandle, currentAddress + 0x10);
            Console.WriteLine("-Pointer3: {0:X}", currentAddress);

            currentAddress = getPointer(processHandle, currentAddress + 0x10);
            Console.WriteLine("-Pointer4: {0:X}", currentAddress);

            int tabsAddress = getPointer(processHandle, currentAddress + 0x30);
            Console.WriteLine("-Tabs Pointer: {0:X}", tabsAddress);

            Console.WriteLine("\n\n***************************************************\n\n");

            //pointer to currently opened tab is at tabsAddress + 0x30
            int currentTabAddress = getPointer(processHandle, tabsAddress + 0x30);
            int currentTabNamePointer = getPointer(processHandle, currentTabAddress + 0x2C);
            string currentTabName = getString(processHandle, currentTabNamePointer, 16);
            Console.WriteLine("--Tab[Current/0] @{0:X}: {1}", currentTabAddress, currentTabName);
            int currentTabMessagesDataStructure = getPointer(processHandle, currentTabAddress + 0x24);
            iterateTabMessages(processHandle, 0, currentTabMessagesDataStructure);
            Console.WriteLine("\n\n***************************************************\n\n");

            iterateTabs(processHandle, tabsAddress);
        }

        public static void iterateTabs(int processHandle, int tabsAddress) {
            //first tab node address is tabsAddress + 0x24
            int tabNodeAddress = getPointer(processHandle, tabsAddress + 0x24);
            int tabCount = 0;

            //repeat until tab node address = 0x0
            while (tabNodeAddress != 0x0) {
                tabCount++;

                //use 0x30 for longer name (possibly upto 30 bytes)
                //0x2C will use '...' for names longer than 15 chars
                int tabNamePointer = getPointer(processHandle, tabNodeAddress + 0x2C);
                string tabName = getString(processHandle, tabNamePointer, 16);
                Console.WriteLine("--Tab[{0}] @{1:X}: {2}", tabCount, tabNodeAddress, tabName);

                int tabMessagesDataStructure = getPointer(processHandle, tabNodeAddress + 0x24);
                iterateTabMessages(processHandle, tabCount, tabMessagesDataStructure);

                Console.WriteLine("\n\n***************************************************\n\n");

                //next tab node pointer is current tab node address + 0x10
                tabNodeAddress = getPointer(processHandle, tabNodeAddress + 0x10);
            }
        }

        public static void iterateTabMessages(int processHandle, int tabNumber, int tabMessagesDataStructure) {
            //first tab messages node address is tabMessagesDataStructure + 0x10
            int tabMessageNodeAddress = getPointer(processHandle, tabMessagesDataStructure + 0x10);
            int messageCount = 0;

            while (tabMessageNodeAddress != 0x0) {
                messageCount++;
                int tabMessageAddress = getPointer(processHandle, tabMessageNodeAddress + 0x4C);
                //max message input is 255 characters, but the Advertising channel has 400+ character initial message
                string tabMessage = getString(processHandle, tabMessageAddress, 255);
                Console.WriteLine("----Tab[{0}] Message[{1}] @{2:X}: {3}", tabNumber, messageCount, tabMessageAddress, tabMessage);

                //next tab messages node pointer is current tab messages node address + 0x5C
                tabMessageNodeAddress = getPointer(processHandle, tabMessageNodeAddress + 0x5C);
            }
        }

        public static int getPointer(int processHandle, int address) {
            byte[] pointerBuffer = new byte[4];
            int bytesRead = 0;
            ReadProcessMemory(processHandle, address, pointerBuffer, 4, ref bytesRead);

            //this broke things on my intel machine.. not sure if needed for NOT LittleEndian??
            //if (BitConverter.IsLittleEndian)
            //    Array.Reverse(pointerBuffer);

            return BitConverter.ToInt32(pointerBuffer, 0);
        }

        public static string getString(int processHandle, int address, int size)
        {
            byte[] pointerBuffer = new byte[size];
            int bytesRead = 0;
            ReadProcessMemory(processHandle, address, pointerBuffer, size, ref bytesRead);

            //this broke things on my intel machine.. not sure if needed for NOT LittleEndian??
            //if (BitConverter.IsLittleEndian)
            //    Array.Reverse(pointerBuffer);

            for (int i = 0; i < pointerBuffer.Length; i++) {
                if (pointerBuffer[i] == 0) {
                    size = i;
                    break;
                }
            }

            return System.Text.Encoding.Default.GetString(pointerBuffer, 0, size);
        }

        public static bool IsFlashClient() {
            return TibiaClientName.Contains("flash", StringComparison.OrdinalIgnoreCase) || TibiaClientName.Contains("chrome", StringComparison.OrdinalIgnoreCase);
        }
    }
}
