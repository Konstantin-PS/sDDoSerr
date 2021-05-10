/**
  * sDDoSerr - the programm for simulate shrew (D)DoS attack.
  * 
  * Модуль парсера командной строки.
  * Для парсинга конфигурационного ini файла используется 
  * сторонний модуль minIni.
  * 
  * v.1.3.6.24a от 10.05.21.
  **/

/**
    This file is part of sDDoSerr.
sDDoSerr is a research program for emulating shrew (D)DoS traffic 
(in development).
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
    embed any of sDDoSerr modules (code components) into other programs.

    sDDoSerr is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with sDDoSerr.  If not, see <https://www.gnu.org/licenses/>.


    Этот файл — часть sDDoSerr.
sDDoSerr — это исследовательская программа для эмуляции "shrew" (D)DoS 
трафика (в разработке). 
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
   любой из модулей (компонентов кода) sDDoSerr в другие программы.

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
#include "minIni.h" //Сторонний парсер ini-файлов.
#include <stdlib.h> //Для atoi() в парсинге аргументов.
#include <ctype.h> //Для isdigit().
#include <math.h> //Для llround.

#include "cmd_parser.h"


const char *argp_program_bug_address = "konstantin.p.96@gmail.com";
const char *argp_program_version = "v.1.4.1.24a";

//Функция парсера.
/*
 *  Надо придумать входные параметры для программы.
 * Сделать обязательными.
 * -h, --host - адрес (с двоеточием, т.к. нужен аргумент).
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

/* Конфигурационный файл. */
const char config[] = "config.ini";


//Внутренние переменные со значениями из конфиг-файла.
unsigned long long int  message_size = 0; //Максимальный размер сообщения (+ к размеру пакета).
int  num_deltas = 0; //Количество -дельт от размера сообщения
int  protocol = 0; //Протокол.
int  host_size = 100; //Максимальный размер имени хоста.
int  procnum = 1; //Количество процессов/потоков.
int  pack_size = 1; //Количество пакетов в одной "пачке", т.е. её размер.
long int start_pause = 0; //Начальная пауза между отправкой \
"пачек" пакетов, в мс.
int  debug; //Флаг дебага. 0 - выкл.; 1 - вкл.; 2 - подробно.


/* 
* Структура настроек, в которую будут записываться 
* все параметры программы (в том числе, после переопределения 
* аргументами командной строки).
*/


/* Сдвоенная функция считывания конфига и парсинга командной строки. */
struct Settings *parser (int argc, char *argv[])
{
    
    /* Динамическое выделение памяти под структуру настроек
     * settings типа Settings. 
     * 
     * !Для доступа к полям структуры по указателю на неё надо 
     * использовать не "settings.поле", а "settings->поле"!
     * */
    //struct Settings *settings;
    settings = NULL;
    settings = malloc(sizeof(struct Settings));
    
    /* Считываем настройки по-умолчанию из конфигурационного файла. */
    message_size = ini_getl("General", "MessageSize", -1, config);
    num_deltas = ini_getl("General", "NumDeltas", -1, config);
    protocol = ini_getl("General", "Protocol", -1, config);
    host_size = ini_getl("General", "HostSize", -1, config);
    procnum = ini_getl("General", "ProcNum", -1, config);
    pack_size = ini_getl("General", "NumOfPacketsInPack", -1, config);
    start_pause = ini_getl("General", "StartPause", -1, config);
    debug = ini_getl("General", "Debug", -1, config);
    
    
    
    /* Типа защиты от запуска без аргументов. */
    if (argc <= 1)
        {
            fprintf (stderr, \
            "Не заданы обязательные параметры (Host, Port)! \n" \
            "Запустите программу с параметром --help для помощи. \n");
            free(settings);
            exit(EXIT_FAILURE);
        }
    
    /* Считываем и парсим аргументы командной строки. 
     * Переменные под адрес хоста и порт.
     */
    
    char *host = NULL;
    if ((host = malloc(host_size*sizeof(char))) == NULL)
    {
        printf("Ошибка выделения памяти под имя хоста! \n");
        settings->host = NULL;
        return settings;
    }

    
    char *port[5] = {NULL};
    //! unsigned short int от 0 до 65535. %hi
    //Функции getaddrinfo нужен порт в виде char!
    
    /* Структура с параметрами работы парсера. */
    struct argp_option options[] =
    {
        {"host", 'h', "HOST", 0, "Host - Hostname, URL or IP"},
        {"port", 'p', "PORT", 0, "Port"},
        {"debug", 'd', "[0|1|2]", OPTION_HIDDEN,\
        "Debug flag. Print debug messages: 0 - off, 1 - on, 2 - more"},
        {0}
    };
    
    /**
     * !Костыль!
     * Ключ дебага -d --debug скрыт, чтобы можно было запскать без него.
     * Если установить опцию OPTION_ARG_OPTIONAL, то без ключа работает,
     * а с ним вылетает ошибка сегментации.
     **/
    
    /**
     * Пример одного поля структуры.
     * {"имя", 'ключ', "значение", опция, "подсказка"},
     * Для использования только полного имени ключ записать как 
     * простое число (и в case так же).
     * Для использования без параметра в поле "значение" записать 0.
     * Можно скрыть ключ и всё с ним связанное из хелпа установив
     * опцию OPTION_HIDDEN.
     * Ещё есть опция OPTION_ARG_OPTIONAL для опциональных ключей.
     **/
       
     
    /* Функция парсера командной строки. */
    int parse_opt (int key, char *arg, struct argp_state *state)
    {
    switch (key)
        {        
        case 'h':
            {
                strcpy(host, arg); //Запись значения в переменную.
                //host = arg; //Запись значения, плохой вариант!
                //host[strlen(arg)+1] = '\0'; //Типа терминации.
                break;
            }
        
        case 'p':
            {
                /* Проверка на наличие посторонних символов в 
                 * аргументе порта. */
                for (int i = 0; i < strlen(arg); i++)
                {                    
                    //printf("код arg[i] = %i \n", arg[i]);
                    
                    if (isdigit(arg[i]) == 0)
                    {
                        fprintf(stderr, \
                        "Неправильный порт! Вводите только цифры. \n");
                        //argp_failure (state, 1, 0, \
                        "В порт введено что-то, кроме цифр!");
                        exit(EXIT_FAILURE);
                    }
                    
                }
                
                //port = atoi(arg); //Перевод строки в число.
                //port = arg;
                *port = arg;
                break;
            }
            
        case 'd':
            {
                //debug = 1;
                
                for (int i = 0; i < strlen(arg); i++)
                {                       
                    if (isdigit(arg[i]) == 0)
                    {
                        fprintf(stderr, \
                        "Неправильный флаг дебага! Введите число. \n");
                        exit(EXIT_FAILURE);
                    }
                }
                
                debug = atoi(arg);
                break;
            }
        
        }
    
    return 0;
    }
    
    //69 стр.
    //-----тип | имя-=--опции  , error_t  , char *args_doc, char *doc
    struct argp argp = {options, parse_opt, 0,\
        "sDDoSerr - the research programm for emulate shrew \
(D)DoS attack traffic. \n\
DDoSerr Copyright © 2019-2021 Konstantin Pankov, Mikhail Riapolov. \n\
(e-mail: konstantin.p.96@gmail.com) \v" 
"To exit the program, press 'q' (or 'Q', or 'й', or 'Й'). \n\
Please wait for full completion of the program runtime after pressing \
the exit button."};

    
    /* Запуск парсера. */
    argp_parse(&argp, argc, argv, 0, 0, 0);
    
    
    /* Записываем конечные значения параметров в структуру. */
    
    //strcpy (settings->host, "host"); //Строки записывать таким образом.
    
    settings->host = host; //Передаётся адрес указателя
    settings->port = *port; //Передаётся значение по указателю
    settings->message_size = message_size;
    settings->num_deltas = num_deltas;
    settings->protocol = protocol;
    settings->procnum = procnum;
    settings->pack_size = pack_size;
    settings->start_pause = start_pause;
    settings->debug = debug;

    
    if (settings->debug == 1)
        {
            printf("host pointer address: %p \n", host);
            //printf("host pointer data: %s \n", *host); //ломает, ошибка сегментирования
            printf("host pointer data: %s \n", host); //Работает
            //printf("host pointer to pointer address: %p \n", *host);
            printf("host pointer data: %c \n", *host);//даёт первый символ строки
            //printf("host pointer data [0]: %c \n", host[0]);
            //printf("host pointer data: %s \n", settings->host); //а так работает
            printf("port pointer address: %p \n", port);
            printf("port pointer data: %s \n", *port);
        }
        
    /* Возвращаем структуру со всеми настройками, 
     * включая и переопределённые. */
    return settings;
}
