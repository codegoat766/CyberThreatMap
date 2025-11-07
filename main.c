#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>  

#define MAX_DEVICES 50
#define MAX_IP_LEN 20
#define CONNECTION_THRESHOLD 4  


#define RESET "\033[0m"
#define RED "\033[1;31m"
#define GREEN "\033[1;32m"
#define YELLOW "\033[1;33m"
#define CYAN "\033[1;36m"
#define MAGENTA "\033[1;35m"


struct Node {
    int deviceIndex;
    struct Node* next;
};


struct Device {
    char ip[MAX_IP_LEN];
    struct Node* adjacencyList;
    int connectionCount;
    int flagged;  
};


struct Device network[MAX_DEVICES];
int deviceCount = 0;


int findDeviceIndex(char* ip) {
    for (int i = 0; i < deviceCount; i++)
        if (strcmp(network[i].ip, ip) == 0)
            return i;
    return -1;
}


int addDevice(char* ip) {
    int index = findDeviceIndex(ip);
    if (index != -1)
        return index;

    if (deviceCount >= MAX_DEVICES) {
        printf(RED "Error: Maximum number of devices reached.\n" RESET);
        return -1;
    }

    strcpy(network[deviceCount].ip, ip);
    network[deviceCount].adjacencyList = NULL;
    network[deviceCount].connectionCount = 0;
    network[deviceCount].flagged = 0;
    return deviceCount++;
}


void appendConnectionToCSV(const char* filename, char* ip1, char* ip2) {
    FILE* file = fopen(filename, "a");
    if (!file) {
        printf(RED "Error: Could not open %s for writing.\n" RESET, filename);
        return;
    }
    fprintf(file, "%s,%s\n", ip1, ip2);
    fclose(file);
}


void addConnection(char* ip1, char* ip2) {
    if (strcmp(ip1, ip2) == 0) {
        printf(RED "Error: Cannot connect a device to itself.\n" RESET);
        return;
    }

    int i1 = addDevice(ip1);
    int i2 = addDevice(ip2);
    if (i1 == -1 || i2 == -1) return;

    
    struct Node* temp = network[i1].adjacencyList;
    while (temp) {
        if (temp->deviceIndex == i2) {
            printf(YELLOW "Warning: Connection already exists between %s and %s.\n" RESET, ip1, ip2);
            return;
        }
        temp = temp->next;
    }

    
    struct Node* newNode = malloc(sizeof(struct Node));
    newNode->deviceIndex = i2;
    newNode->next = network[i1].adjacencyList;
    network[i1].adjacencyList = newNode;

    newNode = malloc(sizeof(struct Node));
    newNode->deviceIndex = i1;
    newNode->next = network[i2].adjacencyList;
    network[i2].adjacencyList = newNode;

    network[i1].connectionCount++;
    network[i2].connectionCount++;

    printf(GREEN "Connection added successfully: %s <-> %s\n" RESET, ip1, ip2);

    
    appendConnectionToCSV("connections.csv", ip1, ip2);

    
    if (network[i1].connectionCount > CONNECTION_THRESHOLD && !network[i1].flagged) {
        network[i1].flagged = 1;
        printf(RED "[!] WARNING: Device %s now has %d connections and has been FLAGGED as suspicious!\n" RESET,
               network[i1].ip, network[i1].connectionCount);
    }

    if (network[i2].connectionCount > CONNECTION_THRESHOLD && !network[i2].flagged) {
        network[i2].flagged = 1;
        printf(RED "[!] WARNING: Device %s now has %d connections and has been FLAGGED as suspicious!\n" RESET,
               network[i2].ip, network[i2].connectionCount);
    }
}


void loadConnectionsFromCSV(const char* filename) {
    FILE* file = fopen(filename, "r");
    if (!file) {
        printf(YELLOW "No existing CSV found. Starting with empty network.\n" RESET);
        return;
    }

    char line[100];
    char ip1[MAX_IP_LEN], ip2[MAX_IP_LEN];
    int loaded = 0;

    while (fgets(line, sizeof(line), file)) {
        if (sscanf(line, "%[^,],%s", ip1, ip2) == 2) {
            addConnection(ip1, ip2);
            loaded++;
        }
    }

    fclose(file);
    printf(GREEN "Loaded %d connections from %s\n" RESET, loaded, filename);
}


void displayNetwork() {
    system("clear || cls");
    printf(CYAN "\n====== CYBERSECURITY THREAT MAP ======\n" RESET);
    printf("Total Devices: %d\n", deviceCount);
    printf("--------------------------------------\n");

    for (int i = 0; i < deviceCount; i++) {
        if (network[i].flagged)
            printf(RED "[FLAGGED] %s (%d connections): " RESET,
                   network[i].ip, network[i].connectionCount);
        else if (network[i].connectionCount > CONNECTION_THRESHOLD)
            printf(RED "[SUSPICIOUS] %s (%d connections): " RESET,
                   network[i].ip, network[i].connectionCount);
        else
            printf(GREEN "%s (%d): " RESET,
                   network[i].ip, network[i].connectionCount);

        struct Node* temp = network[i].adjacencyList;
        while (temp) {
            printf(YELLOW "%s " RESET, network[temp->deviceIndex].ip);
            temp = temp->next;
        }
        printf("\n");
    }

    printf("--------------------------------------\n");

    
    printf(MAGENTA "\n--- CSV File: connections.csv ---\n" RESET);
    FILE* file = fopen("connections.csv", "r");
    if (file) {
        char ch;
        while ((ch = fgetc(file)) != EOF)
            putchar(ch);
        fclose(file);
    } else {
        printf(YELLOW "No CSV file found.\n" RESET);
    }
    printf("--------------------------------------\n");
}


void detectAnomalies() {
    printf(MAGENTA "\n--- Anomaly Detection Report ---\n" RESET);
    int found = 0;

    for (int i = 0; i < deviceCount; i++) {
        if (network[i].flagged || network[i].connectionCount > CONNECTION_THRESHOLD) {
            printf(RED "[!] ALERT: %s has %d connections and is FLAGGED as suspicious.\n" RESET,
                   network[i].ip, network[i].connectionCount);
            found = 1;
        }
    }

    if (!found)
        printf(GREEN "No suspicious devices detected.\n" RESET);
}


void simulateRandomConnections(const char* filename, int iterations, int delaySeconds) {
    printf(CYAN "\n--- Starting Live Simulation ---\n" RESET);
    char ip1[MAX_IP_LEN], ip2[MAX_IP_LEN];

    for (int i = 0; i < iterations; i++) {
        sprintf(ip1, "192.168.%d.%d", rand() % 5 + 1, rand() % 50 + 1);
        sprintf(ip2, "192.168.%d.%d", rand() % 5 + 1, rand() % 50 + 1);
        if (strcmp(ip1, ip2) == 0) continue;

        addConnection(ip1, ip2);
        appendConnectionToCSV(filename, ip1, ip2);

        printf(GREEN "Simulated connection: %s <-> %s\n" RESET, ip1, ip2);
        sleep(delaySeconds);
    }

    printf(MAGENTA "\nSimulation complete! %d connections added.\n" RESET, iterations);
}


void menu() {
    int choice;
    char ip1[MAX_IP_LEN], ip2[MAX_IP_LEN];

    while (1) {
        printf(CYAN "\nMenu:\n" RESET);
        printf("1. Add Connection (Manual Input)\n");
        printf("2. Display Network Map\n");
        printf("3. Detect Anomalies\n");
        printf("4. Load Connections from CSV File\n");
        printf("5. Simulate Random Connections\n");
        printf("6. Exit\n");
        printf("Enter your choice: ");
        scanf("%d", &choice);

        switch (choice) {
            case 1:
                printf("Enter IP 1: ");
                scanf("%s", ip1);
                printf("Enter IP 2: ");
                scanf("%s", ip2);
                addConnection(ip1, ip2);
                break;
            case 2:
                displayNetwork();
                break;
            case 3:
                detectAnomalies();
                break;
            case 4:
                loadConnectionsFromCSV("connections.csv");
                break;
            case 5:
                simulateRandomConnections("connections.csv", 10, 1);
                break;
            case 6:
                printf("Exiting...\n");
                exit(0);
            default:
                printf(RED "Invalid choice! Try again.\n" RESET);
        }
    }
}

int main() {
    srand(time(NULL));
    //loadConnectionsFromCSV("connections.csv"); // Auto-load on startup
    menu();
    return 0;
}
