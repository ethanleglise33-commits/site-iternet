const supabaseUrl = "https://urvkactimexdmvstjcxo.supabase.co"
const supabaseKey = "sb_publishable_C_c5Zv-8KJkqSDJmCZlsCg_1cTt2_EV"

const supabase = supabase.createClient(supabaseUrl, supabaseKey)

async function addMessage(){

 const text = document.getElementById("message").value

 await supabase
  .from("messages")
  .insert([{text:text}])

 loadMessages()
}

async function loadMessages(){

 const { data } = await supabase
  .from("messages")
  .select("*")

 const list = document.getElementById("messages")
 list.innerHTML=""

 data.forEach(msg=>{
   const li=document.createElement("li")
   li.textContent=msg.text
   list.appendChild(li)
 })
}

loadMessages()