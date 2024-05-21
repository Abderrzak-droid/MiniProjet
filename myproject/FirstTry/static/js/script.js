$(document).ready(function() {
  var table = $('#example').DataTable({
      // Disable sorting on the last column
      "columnDefs": [
          { "orderable": false, "targets": 3 }
      ],
      language: {
          // Customize pagination prev and next buttons: use arrows instead of words
          'paginate': {
              'previous': '<span class="fa fa-chevron-left"></span>',
              'next': '<span class="fa fa-chevron-right"></span>'
          },
          // Customize number of elements to be displayed
          "lengthMenu": 'Display <select class="form-control input-sm">'+
          '<option value="10">10</option>'+
          '<option value="20">20</option>'+
          '<option value="30">30</option>'+
          '<option value="40">40</option>'+
          '<option value="50">50</option>'+
          '<option value="-1">All</option>'+
          '</select> results'
      }
  });

  // Add click event listener for toggling details
  $('#example tbody').on('click', '.toggle-details', function () {
      var tr = $(this).closest('tr');
      var row = table.row(tr);
      var details = $(this).data('details');

      if (row.child.isShown()) {
          // This row is already open - close it
          row.child.hide();
          tr.removeClass('shown');
      } else {
          // Open this row
          row.child(format(details)).show();
          tr.addClass('shown');
      }
  });

  // Example function to format details
  function format(details) {
      return '<table cellpadding="5" cellspacing="0" border="0" style="padding-left:50px;">'+
          '<tr>'+
              '<td>Details:</td>'+
              '<td>'+details+'</td>'+
          '</tr>'+
      '</table>';
  }
});