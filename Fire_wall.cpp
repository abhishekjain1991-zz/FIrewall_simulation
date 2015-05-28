
#include <cstdlib>
#include <string>
#include <sstream>
#include <vector>
#include <stack>
#include <fstream>
#include <unordered_map>
#include <set>
#include <iostream>


using namespace std;

/*
 * 
 */
//used to parse the rule string
vector<string> line_input;

//used to parse input string
vector<string> line_input2;

//used to store the subnets
set<int,greater<int> > mask_val;

//flags required for parsing
int slash=0,range=0;

//unordered map for storing minimum ips

stack<string> inputstring;

//The Dns Cache for storing dns entries
unordered_map<string, set<string> > dns_cache;

//Iterator for the Dns Cache
unordered_map<string, set<string> > :: iterator d1,d2;

//Iterator for the domains within a Dns entry
set<string> :: iterator s1;

//count for * entries
int g_count=0; 

void fill_input_stack(string a)
{
    string buf; // Have a buffer string
    stringstream ss(a); // Insert the string into a stream
    while (ss >> buf)
    {   

        inputstring.push(buf);
    }
    
    
}

string replace_space_with_dot(string str)
{
    int i=0;
    while(str[i])
    {
        if(str[i]=='.')
        {
            
            str[i]=' ';
            
        }
        i++;
    }
    return str;
}



void add_rules()
{
    string value,tempv;
    set<string> temp;
    while(!inputstring.empty())
    {
        value=inputstring.top();

      
        d1=dns_cache.find(value);

        if(d1==dns_cache.end())
        {   
            inputstring.pop();
            if(!inputstring.empty())
            {
                tempv=inputstring.top();
                if(tempv=="*")
                {
                    inputstring.pop();
                    tempv=inputstring.top();
                }
                //cout<<"inserting "<<tempv<<endl;
                temp.insert(tempv);
            }
            else
            {   
                //cout<<"entering "<<value<<endl;
                temp.insert(value);
            }
            
            pair<string,set<string> >hash (value,temp);
            dns_cache.insert(hash);
            temp.clear();
            
            
        }
        else
        {
            inputstring.pop();
            if(!inputstring.empty())
            {
                tempv=inputstring.top();
                //cout<<"inserting "<<tempv<<endl;
                (d1->second).insert(tempv);
                
            }
            else
            {   
                //cout<<"entering "<<value<<endl;
                (d1->second).insert(value);
            }
            
            
        }
        
        
    }
}
void empty_input_stack()
{
 while(!inputstring.empty())
 {
     inputstring.pop();
 }
}



void evaluate_rules()
{
    string value;
    d1=dns_cache.begin();
    while(!inputstring.empty())
    {
        d1=dns_cache.find(inputstring.top());
        if(d1!=dns_cache.end())
        {
            //cout<<" i found "<<inputstring.top()<<endl;
          inputstring.pop();
          if(!inputstring.empty())
          {
              d2=dns_cache.find(inputstring.top());
          }
          else
          {
              d2=dns_cache.end();
              
          }
              
          if(d2!=dns_cache.end())
          {
              
              continue;
          }
          else
          {
           if(d1->second.find("pass")!=d1->second.end())
            {
              cout<<"Packet should pass"<<endl;
              empty_input_stack();
              break;
            }
           else if(d1->second.find("fail")!=d1->second.end())
            {
               cout<<"Packet should drop"<<endl;
               empty_input_stack();
               break;
            }
           else
            {
               cout<<"apply default rule"<<endl;
               empty_input_stack();
               break;
            }
           }
           
          }
        else
        {
            cout<<"no rule applied"<<endl;
            empty_input_stack();
               break;
            
        }
         }
}


class protocol{
public:
    protocol(string m_result, int min, int max):result(m_result),l_port_number(min),m_port_number(max)
    {}

    string result;
    int l_port_number;
    int m_port_number;
    
    void proto_print()
    {
        cout<<"my port numbers are "<<l_port_number<<" and "<<m_port_number<<endl;
        cout<<"my result is "<<result<<endl;
    }
};

class Ip_rules
{
public:
    
    unordered_multimap<string,protocol> proto;
    Ip_rules( string m_protocol, string m_result, int min_port,int max_port)
    {
        protocol pr(m_result,min_port,max_port);
        pair<string,protocol> temp_pair(m_protocol,pr);
        proto.insert(temp_pair);
    }

    
};
unordered_map<uint32_t,Ip_rules> min_ip;

unordered_map<uint32_t,Ip_rules> :: iterator umap_it = min_ip.begin();



string replace_space_with_dot_protocol(string str)
{
    int i=0;
    while(str[i])
    {
        if(str[i]=='.' )
        {
            
            str[i]=' ';
            
        }
        if(str[i]=='/')
        {
            str[i]=' ';
            slash=1;
        }
        if(str[i]=='-')
        {
            str[i]=' ';
            range=1;
        }
        
        
        i++;
    }
    return str;
}

void prepare_input_vector(string a)
{
    string buf; 
    stringstream ss(a); 
    int count=0;
    while (ss >> buf)
    {
        if(count==2 && buf=="any")
        {
           for(int j=0;j<4;j++)
           {
              line_input.push_back("256"); 
              count++;
           }
        }
        else if(count==6 && slash==0)
        {
            line_input.push_back(to_string(0));
            line_input.push_back(buf);
            count++;
        }
        else{
            line_input.push_back(buf);
            count++;
        }
    }
    
    if(line_input.size()==8)
    {
        line_input.push_back(*(--line_input.end()));
    }
    range=0;
    slash=0;
    vector<string> :: iterator it= line_input.begin();

    
}


void prepare_packet_vector(string a)
{
    string buf; 
    stringstream ss(a); 
    while (ss >> buf)
    {
        line_input2.push_back(buf);
    }
    //get the input ip address first
    int d=stoi(line_input2[1]);
    int e=stoi(line_input2[2]);
    int f=stoi(line_input2[3]);
    int g=stoi(line_input2[4]);
    uint32_t ip_add_old=(d<<24)+(e<<16)+(f<<8)+g;
    uint32_t ip_add;
    //cout<<"og ip is "<<ip_add_old<<endl;
    
    int s_count=0;
    
    //try to mask and find an ip in the has table
    set<int, greater<int> > :: iterator s_it=mask_val.begin();
    int mask=0;
    int found_ip=0;
    while(s_it!=mask_val.end())
    {
        
        mask=0xffffffff<<(32-(*s_it));
        ip_add=mask&ip_add_old;
        //cout<<"ip address while finding is "<<ip_add<<"and mask value is "<<*s_it<<endl;
        if(min_ip.find(ip_add)!=min_ip.end())
        {

            umap_it=min_ip.find(ip_add);

            auto range= (umap_it->second).proto.equal_range(line_input2[0]);
            for(auto it_temp = range.first; it_temp != range.second; ++it_temp)
            {
                //cout<<it_temp->second.l_port_number<<" "<<it_temp->second.m_port_number<<"  "<<line_input2[5]<<endl;
                if(it_temp->second.l_port_number==it_temp->second.m_port_number)
                {
                    if(it_temp->second.l_port_number==stoi(line_input2[5]))
                    {
                        cout<<"Packet should "<<it_temp->second.result<<endl;
                        line_input2.clear();
                        found_ip=1;
                        return;
                    }
                    else if(it_temp->second.l_port_number==-1)
                    {
                       cout<<"Packet should "<<it_temp->second.result<<endl;
                       line_input2.clear();
                       found_ip=1;
                        return;
                    }
                }
                else if(it_temp->second.l_port_number<it_temp->second.m_port_number)
                {
                    if(stoi(line_input2[5])>=it_temp->second.l_port_number && it_temp->second.m_port_number>=stoi(line_input2[5]))
                    {
                        //cout<<" i am here"<<endl;
                        cout<<"Packet should "<<it_temp->second.result<<endl;
                        line_input2.clear();
                        found_ip=1;
                        return;
                    }
                }
            }
        }
        s_it++;
    }
    //check in all after this
    if(!found_ip)
    {
     int d=256;
     int e=256;
     int f=256;
     int g=256;
     ip_add=(d<<24)+(e<<16)+(f<<8)+g;
     umap_it=min_ip.find(ip_add);

     auto range= (umap_it->second).proto.equal_range(line_input2[0]);
     for(auto it_temp = range.first; it_temp != range.second; ++it_temp)
        {
                if(it_temp->second.l_port_number==it_temp->second.m_port_number)
                {
                    if(it_temp->second.l_port_number==stoi(line_input2[5]))
                    {
                        cout<<"Packet should "<<it_temp->second.result<<endl;
                        line_input2.clear();
                        return;
                    }
                    else if(it_temp->second.l_port_number==-1)
                    {
                        cout<<"Packet should "<<it_temp->second.result<<endl;
                        line_input2.clear();
                        return;
                    }
                }
                else if(it_temp->second.l_port_number<it_temp->second.m_port_number)
                {
                    if(stoi(line_input2[5])>=it_temp->second.l_port_number && it_temp->second.m_port_number>=stoi(line_input2[5]))
                    {
                        
                        cout<<"Packet should "<<it_temp->second.result<<endl;
                        line_input2.clear();
                        return;
                    }
                }
        }
    
    }
    
    cout<<"Packet should do default action "<<endl;
    
    line_input2.clear();
}

void create_table_entry()
{   int a=stoi(line_input[2]);
    int b=stoi(line_input[3]);
    int c=stoi(line_input[4]);
    int d=stoi(line_input[5]);
    uint32_t ip_add=(a<<24)+(b<<16)+(c<<8)+d;
    
    //add mask to existing mask table
    mask_val.insert(stoi(line_input[6]));
    
    int mask=stoi(line_input[6]);
    
    //obtain minimum ip address
    mask=0xffffffff<<32-mask;
    ip_add=mask&ip_add;
    
    
    if(min_ip.find(ip_add)!=min_ip.end())
    {
        //ip is there just update protocol stack for that ip
        umap_it=min_ip.find(ip_add);
        if(line_input[7]=="any")
        {
            protocol pr(line_input[0],-1,-1);
            pair<string,protocol> temp_pair(line_input[1],pr);
            umap_it->second.proto.insert(temp_pair);
        }
        else
        {
            protocol pr(line_input[0],stoi(line_input[7]),stoi(line_input[8]));
            pair<string,protocol> temp_pair(line_input[1],pr);
            umap_it->second.proto.insert(temp_pair);
        }
        
    }
    else
    {
        //add new ip_address with protocol stack for the same
        if(line_input[7]=="any")
        {
         Ip_rules objIp(line_input[1],line_input[0],-1,-1); 
         pair<uint32_t,Ip_rules> ip_hash(ip_add,objIp);
         min_ip.insert(ip_hash);
        }
    else
        { 
        Ip_rules objIp(line_input[1],line_input[0],stoi(line_input[7]),stoi(line_input[8]));
        pair<uint32_t,Ip_rules> ip_hash(ip_add,objIp);
        min_ip.insert(ip_hash);
        }
    }
    line_input.clear();
}
int main(int argc, char** argv) {
    string line;
    ifstream myfile ("rules.txt");
    if (myfile.is_open())
    {
        int find;
        while ( getline (myfile,line) )
        {
            
            if(line.find("TCP")!=string::npos || line.find("ICMP")!=string::npos  || line.find("UDP")!=string::npos)
            {
            //replace anything other than char with space
            line = replace_space_with_dot_protocol(line);
            
            //prepare the input vector
            prepare_input_vector(line);
            
            //add rules
            create_table_entry();
            }
            else
            {
            line.erase(4,4);
            //replace anything other than char with space
            line=replace_space_with_dot(line);
            
            //fill the input stack with the domain names
            fill_input_stack(line);
            
            //add rules
            add_rules();
            }
            
        }
        myfile.close();
    }
    
    cout<<"Done setting rules "<<endl;
    cout<<endl;
    
    ifstream myfile2 ("inputs.txt");
    if (myfile2.is_open())
    {
        while ( getline (myfile2,line) )
        {
            if(line.find("TCP")!=string::npos || line.find("ICMP")!=string::npos  || line.find("UDP")!=string::npos)
            {
            //replace anything other than char with space
            line = replace_space_with_dot_protocol(line);
           
            //Packet being sent in is
            cout<<line<<endl;
           
            //Apply rules for packets that have tcp, udp or icmp
            prepare_packet_vector(line);
            }
            else
            {
            //replace each dot with space
            line.erase(0,4);
            line=replace_space_with_dot(line);
            
            //Packet being sent in is 
            cout<<"packet is  "<<line<<endl;
            
            //fill the input stack with the domain names
            fill_input_stack(line);

            
            //evaluate the rules
            evaluate_rules();
            
            }
           
           
           
        }
    }
    

    return 0;
}

