/* 
 * sDDoSerr - the programm for simulate shrew (D)DoS attack.
 * 
 * Модуль парсера командной строки.
 * Для парсинга конфигурационного ini файла используется 
 * сторонний модуль minIni.
 * 
 * v.1.1.4.7a от 13.02.19.
 */

/**
    This file is part of sDDoSerr.
sDDoSerr is a research program for emulating shrew (D)DoS traffic and
its analysis (in development).
Use this program on your own pril and risk, as with improper use 
there is a risk of disruption of the network infrastucture.
DDoSerr Copyright © 2019 Konstantin Pankov 
(e-mail: konstantin.p.96@gmail.com), Mikhail Riapolov.

    sDDoSerr is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    Any distribution and / or change must be agreed with the authors and
    is prohibited without their permission.
    At this stage of the program development, authors are forbidden to 
    embed any of DDoSerr modules (code components) into other programs.

    sDDoSerr is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with sDDoSerr.  If not, see <https://www.gnu.org/licenses/>.


    Этот файл — часть sDDoSerr.
sDDoSerr — это исследовательская программа для эмуляции "shrew" (D)DoS 
трафика и его анализа (в разработке). 
Используйте эту программу на свой страх и риск, так как при неправильном
применении есть риск нарушения работы сетевой инфраструктуры.
sDDoSerr Copyright © 2019 Константин Панков 
(e-mail: konstantin.p.96@gmail.com), Михаил Ряполов.

   sDDoSerr - свободная программа: вы можете перераспространять ее и/или
   изменять ее на условиях Стандартной общественной лицензии GNU
   в том виде, в каком она была опубликована 
   Фондом свободного программного обеспечения; либо версии 3 лицензии, 
   либо (по вашему выбору) любой более поздней версии.

   Любое распространиение и/или изменение должно быть согласовано с
   авторами и запрещается без их разрешения.
   На данном этапе развития программы авторами запрещается встраивать 
   любой из модулей (компонентов кода) DDoSerr в другие программы.

   sDDoSerr распространяется в надежде, что она будет полезной,
   но БЕЗО ВСЯКИХ ГАРАНТИЙ; даже без неявной гарантии ТОВАРНОГО ВИДА
   или ПРИГОДНОСТИ ДЛЯ ОПРЕДЕЛЕННЫХ ЦЕЛЕЙ. Подробнее см. в Стандартной
   общественной лицензии GNU.

   Вы должны были получить копию Стандартной общественной лицензии GNU
   вместе с этой программой. Если это не так, см.
   <https://www.gnu.org/licenses/>. 
 **/

#include <stdio.h>
#include <string.h>
#include <argp.h> //Парсер командной строки.
#include <argz.h>
#include "minIni.h" //Сторонний парсер ini.
#include <stdlib.h> //Для atoi() в парсинге аргументов.
#include <ctype.h> //Для isdigit().

#include "cmd_parser.h"

//#define URL_LEN 500

const char *argp_program_bug_address = "konstantin.p.96@gmail.com";
const char *argp_program_version = "v.1.1.5.5a";

//Функция парсера.
/*
 *  Надо придумать входные параметры для программы.
 * Сделать обязательными.
 * -u, --url - адрес (с двоеточием, т.к. нужен аргумент).
 * -p, --port - порт, на который отправляются пакеты.
 * 
 * Необязательные, из конфига.
 * -s, --size - размер UDP пакета (количество байт нулей или 
 * по предопределённой константе копированием). Минимум - 46 байт, это
 * только заголовок.
 * --proc - Количество процессов/потоков. Пока не используется.
 * _____________________________________________________________________
 * Необязательные параметры, т.к. должны быть в конфиг-файле.
 * На самом деле, их можно изначально задать в программе, а потом,
 * если нужно, изменить при запуске соответствующим параметром.
 * ? --buffsize - размер буффера.
 * ? --protocol - протокол, по умолчанию любой (ai_protocol = 0).
 * _____________________________________________________________________
 * Должны расчитываться в программе (ключи не нужны?). 
 * --duration -  время дительности импульса (определяет количество 
 * отсылаемых пакетов за указанное время). Порядка 100 мс. 
 * Больше, чем RTT для конкретного случая (RTT из пинга). 
 * До заполнения буффера маршрутизатора.
 * --period - период импульсов (время между восходящми фронтами). 
 * Должен расчитываться автоматически из RTO (примерно 1 сек.) - 
 * он должен быть немного меньше, чем RTO.
 * ? --amplitude - амплитуда импульса. Пока не знаю точно как её можно 
 * будет задавать, но, скорее всего, кол-вом одновременных потоков.
 */

//Конфигурационный файл.
const char config[] = "config.ini";


//Внутренние переменные со значениями из конфиг-файла.
int  max_size; //Максимальный размер сообщения (+ к размеру пакета).
int  num_deltas;
int  buffsize; //Размер буффера передачи.
//char *protocol; //Протокол.
int  protocol; //Протокол.
int  procnum; //Количество процессов/потоков.
int  pack_size; //Количество пакетов в одной "пачке", т.е. её размер.


/* 
* Структура со всеми параметрами, в которую будут записываться 
* все параметры программы (в том числе, после переопределения 
* параметрами командной строки).
*/

/*
//В хэдере.
//Структура настроек ("каркас").
struct Settings {
    //char url[URL_LEN]; //Для жёстко заданного размера.
    char *url;
    char *port;
    int  max_size;
    int  buffsize;
    char *protocol;
    int  procnum;
    };
*/

//Декларация структуры настроек settings типа Settings.
struct Settings settings;

//Сдвоенная функция считывания конфига и парсинга командной строки.
struct Settings parser (int argc, char *argv[])
{
    //Считываем настройки по-умолчанию из конфигурационного файла.
    max_size = ini_getl("General", "MaxSize", -1, config);
    num_deltas = ini_getl("General", "NumDeltas", -1, config);
    buffsize = ini_getl("General", "BuffSize", -1, config);
    protocol = ini_getl("General", "Protocol", -1, config); //* не раб.
    procnum = ini_getl("General", "ProcNum", -1, config);
    pack_size = ini_getl("General", "NumOfPacketsInPack", -1, config);
    
    
    
    //Типа защиты от запуска без аргументов.
    if (argc <= 1)
        {
            fprintf (stderr, \
            "Не заданы обязательные параметры (URL, Port)! \n" \
            "Запустите программу с параметром --help для помощи. \n");
            exit(EXIT_FAILURE);
        }
    
    //Считываем и парсим аргументы командной строки.
    char *url = NULL;
    char *port = NULL;
    
    //Структура с параметрами работы парсера.
    struct argp_option options[] =
    {
        {"url", 'u', "URL", 0, "URL"},
        {"port", 'p', "PORT", 0, "Port"},
        {0}
    };
       
     
    //Функция парсера командной строки.
    //static int parse_opt (int key, char *arg, struct argp_state *state)
    int parse_opt (int key, char *arg, struct argp_state *state)
    {
    switch (key)
        {        
        case 'u':
            {
                //strcpy(url, arg+'\0'); //Не работает.
                //url = arg+'\0'; //Запись значения в переменную с 
                //терминацией. Не работает? А надо ли?
                url = arg; //Запись значения в переменную.
                
                //printf("URL = %s, strlen = %i \n", url, strlen(url));
                //printf("URL = %s \n", url);
                
                break;
            }
        
        case 'p':
            {
                //Проверка на наличие посторонних символов в 
                //аргументе порта.
                for (int i = 0; i < strlen(arg); i++)
                {                    
                    //printf("код arg[i] = %i \n", arg[i]);
                    
                    if (isdigit(arg[i]) == 0)
                    {
                        fprintf(stderr, \
                        "В порт введено что-то, кроме цифр! \n");
                        //argp_failure (state, 1, 0, \
                        "В порт введено что-то, кроме цифр!");
                        exit(EXIT_FAILURE);
                    }
                    
                    
                }
                
                //port = atoi(arg); //Перевод строки в число.
                port = arg;
                
                //printf("Port = %i \n", port);
                
                break;
            }        
        }
    
    return 0;
    }
    //-----тип | имя-=--опции  , error_t  , char *args_doc, char *doc //69 стр.
    struct argp argp = {options, parse_opt, 0,\
                        "Первая подсказка. \v" "Вторая подсказка."};
    //! Сделать проверку и "защиту от дурака" + хелп!
    
    argp_parse (&argp, argc, argv, 0, 0, 0); //Запуск парсера.
    
    
    //Записываем конечные значения параметров в структуру.
    
    //settings.url[URL_LEN] = *url;
    //strcpy (settings.url, "url"); //Строки записывать таким образом.
    
    //strcpy (settings.url, url); //Для жёстко заданного размера.
    
    settings.url = url;
    //printf("length settings.url = %i \n", strlen(settings.url)); //дебаг
    
    settings.port = port;
    
    settings.max_size = max_size;
    settings.num_deltas = num_deltas;
    settings.buffsize = buffsize;
    settings.protocol = protocol;
    settings.procnum = procnum;
    settings.pack_size = pack_size;
    
    //return 0;
    return settings; //Возвращаем структуру со всеми настройками, 
                    //включая и переопределённые.
}

/*-----Для отладки раскомментировать эту ф-ю main и скомпилировать.-----

int main (int argc, char *argv[])
{
    //struct settings[];
    //settings(url, port, size, buffsize, protocol, procnum) = parser (int argc, char *argv[]);
    //int parser = parser ();
    
    //Запуск моей функции объединённого парсера и получение на выходе
    //структуры со всеми настройками программы.
    struct Settings settings = parser (argc, argv);
    
    
    //Отладка.
    
    printf("*DEBUG* \n" \
            "url = %s, port = %s, max_size = %i, buffsize = %i, "\
            "protocol = %s, procnum = %i \n" \
            "*DEBUG* \n",\
            settings.url, settings.port, settings.size,\
            settings.buffsize, settings.protocol, settings.procnum);
    
    return 0;
}
*/
