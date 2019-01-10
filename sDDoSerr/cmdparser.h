/*
 * Заголовочный файл для парсера командной строки.
 * Попытка.
 */

#ifndef CMDPARSER_H
#define CMDPARSER_H

//const char config[];

/*
//Внутренние переменные со значениями из конфиг-файла.
int size; //Размер пакета.
int buffsize; //Размер буффера передачи.
int protocol; //Протокол.
int procnum; //Количество процессов/потоков.
*/

//Другие модули должны знать только об структурах с настройками и 
//функции объединённого парсера.
struct Settings {
    char *url;
    int  port;
    int  size;
    int  buffsize;
    int  protocol;
    int  procnum;
    };

struct Settings settings;

struct Settings parser (int argc, char *argv[]);

//int parse_opt (int, char, struct argp_state);

//struct argp argp;


#endif

//!Сделать после основноо файла (.с).
