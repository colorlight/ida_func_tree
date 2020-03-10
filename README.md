# ida_func_tree
## Function
* gen_call_chain: generate function tree which is called from this function
* r_gen_call_chain: generate function tree which is called to this function
## Usage
* first run the python script in the ida
```
# example
depth = 2
gen_call_chain('function_name', depth)

r_gen_call_chain('function_name',depth)

```
